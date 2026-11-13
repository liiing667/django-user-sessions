from asgiref.sync import sync_to_async
from django.conf import settings
from django.contrib import auth
from django.contrib.sessions.backends.base import CreateError, UpdateError
from django.contrib.sessions.backends.db import SessionStore as DBStore
from django.db import DatabaseError, IntegrityError, router, transaction
from django.utils import timezone


def get_active_session_limit():
    """
    Return the configured maximum number of active sessions per user, or
    ``None`` when no (valid) limit is configured.
    """
    limit = getattr(settings, 'SESSION_ACTIVE_LIMIT', None)
    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
        return None
    return limit


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
        self.user_id = s.user_id
        # do not overwrite user_agent/ip, as those might have been updated
        if self.user_agent != s.user_agent or self.ip != s.ip:
            self.modified = True
        return s

    def create(self):
        super().create()
        self._session_cache = {}

    async def acreate(self):
        while True:
            self._session_key = await self._aget_new_session_key()
            try:
                await self.asave(must_create=True)
            except CreateError:
                continue
            self.modified = True
            return

    def _evict_oldest_sessions(self, using):
        """
        Atomically evict the oldest active sessions of the current user so
        that, after the pending insert, the user does not exceed the
        configured per-user active session limit.

        Only active (non-expired) sessions belonging to the user are taken
        into account. Expired rows are ignored, matching the behaviour of the
        session list view.
        """
        if self.user_id is None:
            return
        limit = get_active_session_limit()
        if limit is None:
            return
        active_sessions = self.model.objects.using(using).filter(
            user_id=self.user_id,
            expire_date__gt=timezone.now(),
        ).order_by('last_activity', 'session_key')
        # Keep the (limit - 1) most recent sessions and evict every older
        # one; one slot is reserved for the session that is about to be
        # inserted. Evaluating the keys inside the transaction makes the
        # eviction atomic together with the pending insert.
        active_keys = list(
            active_sessions.values_list('session_key', flat=True)
        )
        stale_keys = active_keys[: max(0, len(active_keys) - (limit - 1))]
        if stale_keys:
            self.model.objects.using(using).filter(
                session_key__in=stale_keys
            ).delete()

    def save(self, must_create=False):
        """
        Save the current session data to the database.

        When a new authenticated session is created, the oldest active
        sessions of the same user are evicted within the same transaction so
        that the configured per-user active session limit is never exceeded,
        even under concurrent session creation.
        """
        if self.session_key is None:
            return self.create()
        data = self._get_session(no_load=must_create)
        obj = self.create_model_instance(data)
        using = router.db_for_write(self.model, instance=obj)
        try:
            with transaction.atomic(using=using):
                if must_create:
                    self._evict_oldest_sessions(using)
                obj.save(
                    force_insert=must_create,
                    force_update=not must_create,
                    using=using,
                )
        except IntegrityError:
            if must_create:
                raise CreateError
            raise
        except DatabaseError:
            if not must_create:
                raise UpdateError
            raise

    async def asave(self, must_create=False):
        """See save()."""
        if self.session_key is None:
            return await self.acreate()
        data = await self._aget_session(no_load=must_create)
        obj = await self.acreate_model_instance(data)
        using = router.db_for_write(self.model, instance=obj)

        @sync_to_async
        def sync_transaction():
            try:
                with transaction.atomic(using=using):
                    if must_create:
                        self._evict_oldest_sessions(using)
                    obj.save(
                        force_insert=must_create,
                        force_update=not must_create,
                        using=using,
                    )
            except IntegrityError:
                if must_create:
                    raise CreateError
                raise
            except DatabaseError:
                if not must_create:
                    raise UpdateError
                raise

        await sync_transaction()

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

    async def acreate_model_instance(self, data):
        """See create_model_instance()."""
        return self.model(
            session_key=await self._aget_or_create_session_key(),
            session_data=self.encode(data),
            expire_date=await self.aget_expiry_date(),
            user_agent=self.user_agent,
            user_id=self.user_id,
            ip=self.ip,
        )

    def clear(self):
        super().clear()
        self.user_id = None
