from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import TestCase, TransactionTestCase
from django.test.utils import modify_settings
from django.utils.timezone import now

from user_sessions.backends.db import SessionStore
from user_sessions.models import Session


class ClearsessionsCommandTest(TestCase):
    def test_can_call(self):
        Session.objects.create(expire_date=now() - timedelta(days=1),
                               ip='127.0.0.1')
        call_command('clearsessions')
        self.assertEqual(Session.objects.count(), 0)

    def test_only_expired_sessions_are_removed(self):
        Session.objects.create(session_key='expired',
                               expire_date=now() - timedelta(days=1),
                               ip='127.0.0.1')
        Session.objects.create(session_key='active',
                               expire_date=now() + timedelta(days=1),
                               ip='127.0.0.1')
        call_command('clearsessions')
        self.assertEqual(
            list(Session.objects.values_list('session_key', flat=True)),
            ['active'],
        )

    def test_cleanup_after_resume_does_not_revive_session(self):
        """
        Background cleanup and request renewal share one clock: after a
        suspend/resume time jump the expired session is cleaned up and a
        late write from a stale request cannot bring it back.
        """
        store = SessionStore(user_agent='Python/2.7', ip='127.0.0.1')
        store['greeting'] = 'hello'
        store.save()
        key = store.session_key

        # A request on another instance loaded the session while still valid.
        stale = SessionStore(session_key=key, user_agent='Python/2.7', ip='127.0.0.1')
        stale.load()
        stale['late'] = 'write'

        # The machine resumes 15 days later; the session expired meanwhile.
        resumed_at = now() + timedelta(days=15)
        with mock.patch('django.utils.timezone.now', return_value=resumed_at):
            call_command('clearsessions')
            self.assertFalse(Session.objects.filter(session_key=key).exists())
            # The late write from the stale request must not revive it.
            stale.save()
            self.assertFalse(Session.objects.filter(session_key=key).exists())

    def test_cleanup_with_backward_clock_jump_keeps_valid_sessions(self):
        """
        A clock jumping backwards after resume must not make cleanup remove
        sessions that are still valid.
        """
        store = SessionStore(user_agent='Python/2.7', ip='127.0.0.1')
        store['greeting'] = 'hello'
        store.save()
        key = store.session_key

        resumed_at = now() - timedelta(hours=1)
        with mock.patch('django.utils.timezone.now', return_value=resumed_at):
            call_command('clearsessions')
        self.assertTrue(Session.objects.filter(session_key=key).exists())


class MigratesessionsCommandTest(TransactionTestCase):
    @modify_settings(INSTALLED_APPS={'append': 'django.contrib.sessions'})
    def test_migrate_from_login(self):
        from django.contrib.sessions.backends.db import (
            SessionStore as DjangoSessionStore,
        )
        from django.contrib.sessions.models import Session as DjangoSession
        try:
            call_command('migrate', 'sessions')
            call_command('clearsessions')
            user = User.objects.create_user('bouke', '', 'secret')
            session = DjangoSessionStore()
            session['_auth_user_id'] = user.id
            session.save()
            self.assertEqual(Session.objects.count(), 0)
            self.assertEqual(DjangoSession.objects.count(), 1)
            call_command('migratesessions')
            new_sessions = list(Session.objects.all())
            self.assertEqual(len(new_sessions), 1)
            self.assertEqual(new_sessions[0].user, user)
            self.assertEqual(new_sessions[0].ip, '127.0.0.1')
        finally:
            call_command('migrate', 'sessions', 'zero')
