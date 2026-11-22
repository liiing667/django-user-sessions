from datetime import timedelta
from unittest import mock

from django.contrib import auth
from django.contrib.auth.models import User
from django.contrib.sessions.backends.base import CreateError
from django.test import TestCase
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


class SessionExpiryConcurrencyTest(TestCase):
    """
    Security regression tests for the shared clock and generation used by
    the expiry bound, request renewal and the session list.

    An expired session must never become valid again: not through a late
    write from another instance, not through background cleanup racing an
    active request, and not through a clock jumping after suspend/resume
    or a restart. Normal long-running sessions must keep renewing.
    """
    def setUp(self):
        User.objects.create_user('bouke', '', 'secret', id=1)

    def create_store(self, **kwargs):
        kwargs.setdefault('user_agent', 'Python/2.7')
        kwargs.setdefault('ip', '127.0.0.1')
        store = SessionStore(**kwargs)
        store['greeting'] = 'hello'
        store.save()
        return store

    def open_store(self, session_key, **kwargs):
        """Open the same session again, like another request/instance would."""
        kwargs.setdefault('user_agent', 'Python/2.7')
        kwargs.setdefault('ip', '127.0.0.1')
        return SessionStore(session_key=session_key, **kwargs)

    def test_last_activity_does_not_move_backwards_after_resume(self):
        """
        A clock jumping backwards (suspend/resume) must not move
        ``last_activity`` backwards, while the still valid session itself
        is renewed normally.
        """
        store = self.create_store()
        key = store.session_key
        last_activity = Session.objects.get(session_key=key).last_activity

        # The machine suspends and resumes with its clock one hour behind.
        resumed_at = now() - timedelta(hours=1)
        with mock.patch('django.utils.timezone.now', return_value=resumed_at):
            store2 = self.open_store(key)
            self.assertEqual(store2.load(), {'greeting': 'hello'})
            store2['greeting'] = 'hi again'
            store2.save()

        session = Session.objects.get(session_key=key)
        self.assertGreaterEqual(session.last_activity, last_activity)
        self.assertEqual(session.get_decoded(), {'greeting': 'hi again'})

    def test_late_write_does_not_revive_expired_session(self):
        """
        A late write from another instance must not make an expired cookie
        valid again: after the write the session is either fully valid or
        fully invalid, never resurrected.
        """
        store = self.create_store()
        key = store.session_key

        # Another instance serves a request while the session is valid.
        other = self.open_store(key)
        other.load()
        other['late'] = 'write'

        # Meanwhile the session is removed (logout elsewhere, cleanup, ...).
        Session.objects.filter(session_key=key).delete()

        # The late write must be dropped, not resurrect the session.
        other.save()
        self.assertFalse(Session.objects.filter(session_key=key).exists())

        # The old cookie is and stays worthless.
        fresh = self.open_store(key)
        self.assertEqual(fresh.load(), {})

    def test_expired_session_is_not_revived_after_restart(self):
        """
        After a restart with a jumped clock, reading the same session shows
        it as invalid; writing starts a fresh session under a fresh key
        instead of reviving the expired one.
        """
        store = self.create_store()
        key = store.session_key

        # The process restarts after the session expired.
        restarted_at = now() + timedelta(days=15)
        with mock.patch('django.utils.timezone.now', return_value=restarted_at):
            restarted = self.open_store(key)
            self.assertEqual(restarted.load(), {})
            self.assertIsNone(restarted.session_key)

            restarted['greeting'] = 'hello'
            restarted.save()
            self.assertNotEqual(restarted.session_key, key)
            self.assertFalse(Session.objects.filter(session_key=key).exists())
            self.assertTrue(
                Session.objects.filter(session_key=restarted.session_key).exists())

    def test_concurrent_instances_share_clock_and_generation(self):
        """
        Concurrent instances share one clock and one generation: the session
        stays fully valid and ``last_activity`` never regresses, even when
        the other instance's clock is behind.
        """
        store = self.create_store()
        key = store.session_key

        instance_a = self.open_store(key)
        instance_b = self.open_store(key, user_agent='Python/3.3', ip='8.8.8.8')
        instance_a.load()
        instance_b.load()

        instance_a['from'] = 'a'
        instance_a.save()
        last_activity = Session.objects.get(session_key=key).last_activity

        # Instance B writes with a clock that is behind (resumed snapshot).
        with mock.patch('django.utils.timezone.now',
                        return_value=now() - timedelta(hours=1)):
            instance_b['from'] = 'b'
            instance_b.save()

        session = Session.objects.get(session_key=key)
        self.assertGreaterEqual(session.last_activity, last_activity)
        self.assertGreater(session.expire_date, now())
        self.assertEqual(session.user_agent, 'Python/3.3')

    def test_long_session_keeps_renewing(self):
        """
        Compatibility boundary: an active session is renewed on every
        request and can live (much) longer than a single cookie age.
        """
        store = self.create_store()
        key = store.session_key

        # The user keeps coming back every 13 days (cookie age is 14 days).
        for days in (13, 26, 39):
            visit_at = now() + timedelta(days=days)
            with mock.patch('django.utils.timezone.now', return_value=visit_at):
                store = self.open_store(key)
                self.assertEqual(store.load()['greeting'], 'hello')
                store['visits'] = days
                store.save()
                session = Session.objects.get(session_key=key)
                self.assertGreater(session.expire_date, visit_at)
                self.assertGreaterEqual(session.last_activity, visit_at)

        # And the session is still fully valid afterwards.
        final = self.open_store(key)
        self.assertEqual(final.load()['visits'], 39)
