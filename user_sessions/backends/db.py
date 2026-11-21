from django.contrib import auth
from django.contrib.sessions.backends.db import SessionStore as DBStore
from django.db import router, transaction
from django.utils import timezone


class SessionStore(DBStore):
    """
    Implements database session store.
    """
    def __init__(self, session_key=None, user_agent=None, ip=None):
        super().__init__(session_key)
        # Truncate user_agent string to max_length of the CharField
        self.user_agent = user_agent[:200] if user_agent else user_agent
        self.ip = ip
        self.user_id = None
        self._initial_session_key = session_key
        self._invalidated = False

    # Used by superclass to get self.model, which is used elsewhere
    @classmethod
    def get_model_class(cls):
        # Avoids a circular import and allows importing SessionStore when
        # user_sessions is not in INSTALLED_APPS
        from ..models import Session

        return Session

    def __setitem__(self, key, value):
        if key == auth.SESSION_KEY:
            self.user_id = value
        super().__setitem__(key, value)

    # Used in DBStore.load()
    def _get_session_from_db(self):
        s = super()._get_session_from_db()
        if s is None:
            self._session_key = None
            self.user_id = None
            self._invalidated = True
            return None
        self.user_id = s.user_id
        # do not overwrite user_agent/ip, as those might have been updated
        if self.user_agent != s.user_agent or self.ip != s.ip:
            self.modified = True
        return s

    def create(self):
        super().create()
        self._session_cache = {}
        self._invalidated = False

    def save(self, must_create=False):
        if self.session_key is None:
            return self.create()
        if must_create:
            return super().save(must_create=True)

        data = self._get_session()
        if self.session_key is None:
            # The row disappeared or expired while it was being loaded. Use
            # a fresh key instead of updating (and thereby reviving) the old
            # one.
            self._session_cache = data
            return self.create()
        obj = self.create_model_instance(data)
        using = router.db_for_write(self.model, instance=obj)

        values = {}
        for field in obj._meta.concrete_fields:
            if field.primary_key:
                continue
            value = getattr(obj, field.attname)
            if getattr(field, 'auto_now', False):
                value = timezone.now()
            values[field.attname] = value

        # A session key that has been deleted or rotated must stay invalid.
        # A stale request may already have loaded the old row, and Django's
        # Model.save() would otherwise re-insert it when it is no longer in
        # the database. Only update an existing row here; new sessions are
        # inserted exclusively through create().
        with transaction.atomic(using=using):
            saved = self.model.objects.using(using).filter(
                pk=obj.pk,
            ).update(**values)
        if not saved:
            self._invalidated = True

    def cycle_key(self):
        old_key = self.session_key
        if old_key is None:
            old_key = self._initial_session_key
        data = self._session

        if old_key is None:
            self.create()
            self._session_cache = data
            return

        new_key = self._get_new_session_key()
        using = router.db_for_write(self.model)

        # Move the row to its new primary key in one statement. This keeps
        # the old key from remaining valid, and prevents two concurrent
        # rotations from creating two active sessions. If the row has already
        # been deleted or rotated, leave the store pointing at the old key so
        # that a late response cannot recreate it.
        with transaction.atomic(using=using):
            rotated = self.model.objects.using(using).filter(
                pk=old_key,
            ).update(
                session_key=new_key,
                last_activity=timezone.now(),
            )

        self._session_cache = data
        if rotated:
            self._session_key = new_key
            self._invalidated = False
        else:
            # The row was deleted or another request won the rotation first.
            # Keep pointing at the old key so save() cannot create a second
            # active session, and let the middleware remove the stale cookie.
            self._session_key = old_key
            self._invalidated = True
        self.accessed = True
        self.modified = True

    # Used in DBStore.save()
    def create_model_instance(self, data):
        """
        Return a new instance of the session model object, which represents the
        current session state. Intended to be used for saving the session data
        to the database.
        """
        return self.model(
            session_key=self._get_or_create_session_key(),
            session_data=self.encode(data),
            expire_date=self.get_expiry_date(),
            user_agent=self.user_agent,
            user_id=self.user_id,
            ip=self.ip,
        )

    def clear(self):
        super().clear()
        self.user_id = None

    def flush(self):
        super().flush()
        # A logout is terminal for the key this store was opened with. A
        # subsequent login in the same request must start a new session.
        self._initial_session_key = None
