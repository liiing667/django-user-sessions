from datetime import timedelta

from django.contrib import auth
from django.contrib.auth.models import User
from django.contrib.sessions.backends.base import CreateError
from django.test import TestCase
from django.utils.timezone import now

from user_sessions.revocation import revoke_sessions
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

    def test_anonymous_session_is_untouched_by_revocation_querysets(self):
        """
        Anonymous sessions have no user and must therefore be invisible to
        the owner-scoped querysets used by batch revocation.
        """
        anonymous = SessionStore(user_agent='Anon/1.0', ip='10.0.0.9')
        anonymous['cart'] = ['item-1']
        anonymous.save()

        user_qs = User.objects.get(pk=1).session_set.filter(
            expire_date__gt=now())
        report = revoke_sessions(user_qs, [anonymous.session_key])

        # The anonymous row is outside the queryset, so it is reconciled as
        # absent but must physically remain available to its visitor.
        self.assertTrue(
            Session.objects.filter(pk=anonymous.session_key).exists())
        self.assertEqual(
            Session.objects.get(pk=anonymous.session_key).get_decoded(),
            {'cart': ['item-1']},
        )
        self.assertEqual(report.outcome_of(anonymous.session_key).stage,
                         'query')

    def test_expiry_is_respected_throughout_revocation(self):
        """Sessions whose expiry passed are excluded, mirroring the views."""
        expired = SessionStore(user_agent='Old/1.0', ip='10.0.0.10')
        expired.set_expiry(-1)
        expired[auth.SESSION_KEY] = 1
        expired.save()

        active_qs = User.objects.get(pk=1).session_set.filter(
            expire_date__gt=now())
        report = revoke_sessions(active_qs, [expired.session_key])
        self.assertTrue(
            Session.objects.filter(pk=expired.session_key).exists())
        self.assertEqual(
            report.outcome_of(expired.session_key).outcome, 'revoked')

    def test_rolling_update_survives_revocation_of_sibling_sessions(self):
        """
        Deleting sibling devices must not clobber the rolling metadata
        (user agent / ip / last activity) of the surviving current session.
        """
        current = SessionStore(user_agent='Browser/9', ip='10.0.0.11')
        current[auth.SESSION_KEY] = 1
        current.save()
        sibling = SessionStore(user_agent='Browser/8', ip='10.0.0.12')
        sibling[auth.SESSION_KEY] = 1
        sibling.save()

        user_qs = User.objects.get(pk=1).session_set.filter(
            expire_date__gt=now())
        report = revoke_sessions(
            user_qs, [sibling.session_key],
            current_session_key=current.session_key)

        self.assertEqual(report.retained_session_keys,
                         {current.session_key})
        survivor = Session.objects.get(pk=current.session_key)
        self.assertEqual(survivor.user_agent, 'Browser/9')
        self.assertEqual(survivor.ip, '10.0.0.11')
        self.assertAlmostEqual(now(), survivor.last_activity,
                               delta=timedelta(seconds=5))
