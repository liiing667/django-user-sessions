import base64

from django.contrib import auth
from django.contrib.sessions.backends.db import SessionStore as DBStore
from django.contrib.sessions.serializers import PickleSerializer
from django.core.exceptions import SuspiciousOperation
from django.utils.crypto import constant_time_compare
from django.utils.encoding import force_bytes


class SessionStore(DBStore):
    """
    Implements database session store.
    """

    # Serializers that may have produced still-valid session data before
    # ``SESSION_SERIALIZER`` was (re)configured, e.g. pickled sessions from
    # before the switch to JSON. Such sessions remain readable and are
    # transparently re-encoded ("upgraded") with the configured serializer
    # on the next save.
    legacy_serializers = (PickleSerializer,)

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
        if s is None:
            # The session does not exist (anymore) or has expired. Leave the
            # store in a clean, unmodified state instead of crashing.
            self.user_id = None
            return None
        self.user_id = s.user_id
        # do not overwrite user_agent/ip, as those might have been updated
        if self.user_agent != s.user_agent or self.ip != s.ip:
            self.modified = True
        return s

    def decode(self, session_data):
        """
        Decode ``session_data``, falling back to ``legacy_serializers`` for
        sessions that were serialized before ``SESSION_SERIALIZER`` was
        changed (e.g. pickled sessions).

        The payload signature is verified with the current ``SECRET_KEY``
        before anything is deserialized, so the fallback never accepts data
        that the configured serializer would have rejected. Successfully
        decoded legacy sessions are marked as modified, so the next
        ``save()`` re-encodes them with the configured serializer and the
        session is safely upgraded in place.
        """
        try:
            encoded_data = base64.b64decode(force_bytes(session_data))
            # could produce ValueError if there is no ':'
            stored_hash, serialized = encoded_data.split(b":", 1)
            expected_hash = self._hash(serialized)
            if not constant_time_compare(stored_hash, expected_hash):
                raise SuspiciousOperation("Session data corrupted")
        except Exception:
            # ValueError, SuspiciousOperation, binascii.Error, ... If any of
            # these happen, just return an empty dictionary (empty session).
            return {}
        try:
            return self.serializer().loads(serialized)
        except Exception:
            pass
        for legacy_serializer in self.legacy_serializers:
            if legacy_serializer is self.serializer:
                continue
            try:
                session_dict = legacy_serializer().loads(serialized)
            except Exception:
                continue
            # Mark the session as modified so it is re-encoded with the
            # configured serializer on the next save (safe upgrade).
            self.modified = True
            return session_dict
        return {}

    def create(self):
        super().create()
        self._session_cache = {}

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
