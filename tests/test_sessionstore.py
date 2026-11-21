from datetime import timedelta

from django.contrib import auth
from django.contrib.auth.models import User
from django.contrib.sessions.backends.base import CreateError
from django.test import TestCase
from django.utils.timezone import now

from user_sessions.backends.db import SessionStore
from user_sessions.models import Session
from user_sessions.utils import get_session_generation, invalidate_user_sessions


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


class SessionGenerationTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('bouke', '', 'secret', id=1)

    def create_store(self, session_key=None):
        return SessionStore(session_key=session_key,
                            user_agent='Python/2.7', ip='127.0.0.1')

    def create_user_session(self):
        store = self.create_store()
        store[auth.SESSION_KEY] = self.user.pk
        store.save()
        return store

    def test_default_generation(self):
        self.assertEqual(get_session_generation(self.user), 1)

    def test_save_records_current_generation(self):
        store = self.create_user_session()
        session = Session.objects.get(pk=store.session_key)
        self.assertEqual(session.session_generation, 1)

        invalidate_user_sessions(self.user)
        store = self.create_user_session()
        session = Session.objects.get(pk=store.session_key)
        self.assertEqual(session.session_generation, 2)

    def test_invalidate_rejects_existing_sessions(self):
        store = self.create_user_session()
        invalidate_user_sessions(self.user)

        store2 = self.create_store(session_key=store.session_key)
        self.assertEqual(store2.load(), {})
        self.assertIsNone(store2.session_key)
        self.assertFalse(
            Session.objects.filter(pk=store.session_key).exists())

    def test_invalidate_keep_session_keys(self):
        keep = self.create_user_session()
        drop = self.create_user_session()
        invalidate_user_sessions(self.user,
                                 keep_session_keys=[keep.session_key])

        store2 = self.create_store(session_key=keep.session_key)
        store2.load()
        self.assertEqual(store2.user_id, self.user.pk)
        self.assertEqual(
            Session.objects.get(pk=keep.session_key).session_generation, 2)
        self.assertFalse(
            Session.objects.filter(pk=drop.session_key).exists())

    def test_invalidate_returns_new_generation(self):
        self.assertEqual(invalidate_user_sessions(self.user), 2)
        self.assertEqual(invalidate_user_sessions(self.user), 3)
        self.assertEqual(get_session_generation(self.user), 3)

    def test_anonymous_session_unaffected(self):
        store = self.create_store()
        store['FOO'] = 'BAR'
        store.save()
        invalidate_user_sessions(self.user)

        store2 = self.create_store(session_key=store.session_key)
        self.assertEqual(store2.load(), {'FOO': 'BAR'})

    def test_expired_session_still_rejected(self):
        store = self.create_user_session()
        Session.objects.filter(pk=store.session_key).update(
            expire_date=now() - timedelta(days=1))

        store2 = self.create_store(session_key=store.session_key)
        self.assertEqual(store2.load(), {})

    def test_deleted_session_not_recreated_by_concurrent_save(self):
        # Simulate a request that loaded the session before another process
        # cleaned it up: the in-flight response-phase save may write the row
        # back, but it is stamped with the stale generation and rejected on
        # the next load.
        store = self.create_user_session()
        store.load()
        invalidate_user_sessions(self.user)

        store['FOO'] = 'BAR'
        store.save()

        store2 = self.create_store(session_key=store.session_key)
        self.assertEqual(store2.load(), {})
        self.assertFalse(
            Session.objects.filter(pk=store.session_key).exists())
