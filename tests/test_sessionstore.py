import base64
from datetime import timedelta

from django.contrib import auth
from django.contrib.auth.models import User
from django.contrib.sessions.backends.base import CreateError
from django.contrib.sessions.serializers import JSONSerializer, PickleSerializer
from django.test import TestCase
from django.utils.encoding import force_bytes
from django.utils.timezone import now

from user_sessions.backends.db import SessionStore
from user_sessions.models import Session


class SessionStoreTest(TestCase):
    def setUp(self):
        self.store = SessionStore(user_agent='Python/2.7', ip='127.0.0.1')
        User.objects.create_user('bouke', '', 'secret', id=1)

    def test_untouched_init(self):
        self.assertFalse(self.store.modified)
        self.assertFalse(self.store.accessed)

    def test_auth_session_key(self):
        self.assertFalse(auth.SESSION_KEY in self.store)
        self.assertFalse(self.store.modified)
        self.assertTrue(self.store.accessed)

        self.store.get(auth.SESSION_KEY)
        self.assertFalse(self.store.modified)

        self.store[auth.SESSION_KEY] = 1
        self.assertTrue(self.store.modified)

    def test_save(self):
        self.store[auth.SESSION_KEY] = 1
        self.store.save()

        session = Session.objects.get(pk=self.store.session_key)
        self.assertEqual(session.user_agent, 'Python/2.7')
        self.assertEqual(session.ip, '127.0.0.1')
        self.assertEqual(session.user_id, 1)
        self.assertAlmostEqual(now(), session.last_activity,
                               delta=timedelta(seconds=5))

    def test_load_unmodified(self):
        self.store[auth.SESSION_KEY] = 1
        self.store.save()
        store2 = SessionStore(session_key=self.store.session_key,
                              user_agent='Python/2.7', ip='127.0.0.1')
        store2.load()
        self.assertEqual(store2.user_agent, 'Python/2.7')
        self.assertEqual(store2.ip, '127.0.0.1')
        self.assertEqual(store2.user_id, 1)
        self.assertEqual(store2.modified, False)

    def test_load_modified(self):
        self.store[auth.SESSION_KEY] = 1
        self.store.save()
        store2 = SessionStore(session_key=self.store.session_key,
                              user_agent='Python/3.3', ip='8.8.8.8')
        store2.load()
        self.assertEqual(store2.user_agent, 'Python/3.3')
        self.assertEqual(store2.ip, '8.8.8.8')
        self.assertEqual(store2.user_id, 1)
        self.assertEqual(store2.modified, True)

    def test_load_legacy_serialized_session(self):
        """
        Sessions serialized with a legacy serializer (e.g. pickle, from before
        SESSION_SERIALIZER was switched to JSON) must remain readable and must
        be re-encoded with the configured serializer on the next save.
        """
        self.store[auth.SESSION_KEY] = 1
        self.store.save()

        # Re-encode the session data the way a legacy serializer would have.
        session = Session.objects.get(pk=self.store.session_key)
        legacy_store = SessionStore(user_agent='Python/2.7', ip='127.0.0.1')
        legacy_store.serializer = PickleSerializer
        session.session_data = legacy_store.encode({auth.SESSION_KEY: 1})
        session.save()

        store2 = SessionStore(session_key=self.store.session_key,
                              user_agent='Python/2.7', ip='127.0.0.1')
        self.assertEqual(store2.load(), {auth.SESSION_KEY: 1})
        self.assertEqual(store2.user_id, 1)
        # Marked for re-encode, so the session is upgraded on the next save.
        self.assertTrue(store2.modified)

        store2.save()
        session.refresh_from_db()
        encoded = base64.b64decode(force_bytes(session.session_data))
        _, serialized = encoded.split(b':', 1)
        # The payload is now encoded with the configured (JSON) serializer.
        self.assertEqual(JSONSerializer().loads(serialized), {auth.SESSION_KEY: 1})

    def test_load_corrupted_session_data(self):
        self.store[auth.SESSION_KEY] = 1
        self.store.save()
        session = Session.objects.get(pk=self.store.session_key)
        session.session_data = 'not valid session data'
        session.save()
        store2 = SessionStore(session_key=self.store.session_key,
                              user_agent='Python/2.7', ip='127.0.0.1')
        self.assertEqual(store2.load(), {})

    def test_load_nonexistent_session(self):
        store = SessionStore(session_key='does-not-exist',
                             user_agent='Python/2.7', ip='127.0.0.1')
        self.assertEqual(store.load(), {})
        self.assertIsNone(store.user_id)
        self.assertFalse(store.modified)

    def test_load_expired_session(self):
        self.store[auth.SESSION_KEY] = 1
        self.store.save()
        Session.objects.filter(pk=self.store.session_key).update(
            expire_date=now() - timedelta(seconds=1))
        store2 = SessionStore(session_key=self.store.session_key,
                              user_agent='Python/2.7', ip='127.0.0.1')
        self.assertEqual(store2.load(), {})
        self.assertIsNone(store2.user_id)
        self.assertFalse(store2.modified)

    def test_duplicate_create(self):
        s1 = SessionStore(session_key='DUPLICATE', user_agent='Python/2.7', ip='127.0.0.1')
        s1.create()
        s2 = SessionStore(session_key='DUPLICATE', user_agent='Python/2.7', ip='127.0.0.1')
        s2.create()
        self.assertNotEqual(s1.session_key, s2.session_key)

        s3 = SessionStore(session_key=s1.session_key, user_agent='Python/2.7', ip='127.0.0.1')
        with self.assertRaises(CreateError):
            s3.save(must_create=True)

    def test_delete(self):
        # not persisted, should just return
        self.store.delete()

        # create, then delete
        self.store.create()
        session_key = self.store.session_key
        self.store.delete()

        # non-existing sessions, should not raise
        self.store.delete()
        self.store.delete(session_key)

    def test_clear(self):
        """
        Clearing the session should clear all non-browser information
        """
        self.store[auth.SESSION_KEY] = 1
        self.store.clear()
        self.store.save()

        session = Session.objects.get(pk=self.store.session_key)
        self.assertEqual(session.user_id, None)
