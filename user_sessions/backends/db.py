from django.contrib import auth
from django.contrib.sessions.backends.db import SessionStore as DBStore
from django.db.models import DateTimeField, F, Value
from django.db.models.functions import Greatest

from ..utils import now


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

    def save(self, must_create=False):
        # Brand new sessions and forced inserts keep Django's behavior.
        if self.session_key is None or must_create:
            return super().save(must_create=must_create)
        data = self._get_session(no_load=False)
        if self.session_key is None:
            # The session did not exist (anymore) while loading; start with a
            # fresh session key instead of touching the old one.
            return self.create()
        # Renew the session with a single conditional, atomic write. The row
        # is only updated while it is still valid (shared clock): if the
        # session expired or was removed concurrently -- e.g. by the
        # clearsessions command or a logout on another instance -- the late
        # write is dropped instead of resurrecting the expired session.
        # Afterwards the session is either fully valid (data, expiry and
        # activity written together) or fully invalid, never in between.
        current = now()
        self.model.objects.filter(
            session_key=self.session_key,
            expire_date__gt=current,
        ).update(
            session_data=self.encode(data),
            expire_date=self.get_expiry_date(),
            # The generation marker only moves forwards: a clock jumping
            # backwards (suspend/resume) must not decrease last_activity.
            last_activity=Greatest(
                F('last_activity'),
                Value(current, output_field=DateTimeField()),
            ),
            user_agent=self.user_agent,
            user_id=self.user_id,
            ip=self.ip,
        )

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
