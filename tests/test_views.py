from datetime import timedelta

from django.conf import settings
from django.contrib.auth.models import User
from django.db import DatabaseError
from django.test import TestCase
from django.urls import reverse
from django.utils.timezone import now

from user_sessions.models import Session, SessionRevocationEvent
from user_sessions.revocation import clear_injected_failures, inject_failure

from .utils import Client


class ViewsTest(TestCase):
    client_class = Client

    def setUp(self):
        self.user = User.objects.create_user('bouke', '', 'secret')
        assert self.client.login(username='bouke', password='secret')

    def tearDown(self):
        clear_injected_failures()
        super().tearDown()

    def test_list(self):
        self.user.session_set.create(session_key='ABC123', ip='127.0.0.1',
                                     expire_date=now() + timedelta(days=1),
                                     user_agent='Firefox')
        with self.assertWarnsRegex(UserWarning, r"The address 127\.0\.0\.1 is not in the database"):
            response = self.client.get(reverse('user_sessions:session_list'))
        self.assertContains(response, 'Active Sessions')
        self.assertContains(response, 'Firefox')
        self.assertNotContains(response, 'ABC123')

    def test_delete(self):
        session_key = self.client.cookies[settings.SESSION_COOKIE_NAME].value
        response = self.client.post(reverse('user_sessions:session_delete',
                                            args=[session_key]))
        self.assertRedirects(response, '/')

    def test_delete_all_other(self):
        self.user.session_set.create(ip='127.0.0.1', expire_date=now() + timedelta(days=1))
        self.assertEqual(self.user.session_set.count(), 2)
        response = self.client.post(reverse('user_sessions:session_delete_other'))
        with self.assertWarnsRegex(UserWarning, r"The address 127\.0\.0\.1 is not in the database"):
            self.assertRedirects(response, reverse('user_sessions:session_list'))
        self.assertEqual(self.user.session_set.count(), 1)

    def test_delete_some_other(self):
        other = self.user.session_set.create(session_key='OTHER', ip='127.0.0.1',
                                             expire_date=now() + timedelta(days=1))
        self.assertEqual(self.user.session_set.count(), 2)
        response = self.client.post(reverse('user_sessions:session_delete',
                                            args=[other.session_key]))
        with self.assertWarnsRegex(UserWarning, r"The address 127\.0\.0\.1 is not in the database"):
            self.assertRedirects(response, reverse('user_sessions:session_list'))
        self.assertEqual(self.user.session_set.count(), 1)

    def test_delete_other_partial_failure_is_deterministic(self):
        for key in ('DEV-1', 'DEV-2', 'DEV-3'):
            self.user.session_set.create(
                session_key=key, ip='127.0.0.1',
                expire_date=now() + timedelta(days=1),
            )
        inject_failure(SessionRevocationEvent.STAGE_DELETE,
                       'DEV-2', DatabaseError('disk full'))
        try:
            response = self.client.post(
                reverse('user_sessions:session_delete_other'))
        finally:
            clear_injected_failures()

        # The view still redirects, but the report says exactly which device
        # kept its data and at which stage the batch failed.
        self.assertRedirects(response, reverse('user_sessions:session_list'))
        report = response.revocation_report
        self.assertEqual(report.revoked_session_keys, {'DEV-1', 'DEV-3'})
        self.assertEqual(report.failed_session_keys, {'DEV-2'})
        self.assertEqual(report.failures, [{
            'session_key': 'DEV-2',
            'stage': SessionRevocationEvent.STAGE_DELETE,
            'detail': 'DatabaseError: disk full',
        }])
        # Current session plus the failed device are the survivors.
        remaining = set(
            Session.objects.values_list('session_key', flat=True))
        current = self.client.cookies[settings.SESSION_COOKIE_NAME].value
        self.assertEqual(remaining, {current, 'DEV-2'})

        # Retrying with the same batch id finishes the job idempotently.
        retry = self.client.post(reverse('user_sessions:session_delete_other'))
        # The remaining device is retried in a new batch and now succeeds.
        self.assertEqual(retry.revocation_report.failed_session_keys, set())
        self.assertEqual(
            set(Session.objects.values_list('session_key', flat=True)),
            {current},
        )

    def test_delete_other_survives_restart_reconciliation(self):
        # Rows deleted by a previous, crashed attempt (no audit row left)
        # must be reconciled as revoked instead of silently resurfacing.
        ghost = self.user.session_set.create(
            session_key='GHOST', ip='127.0.0.1',
            expire_date=now() + timedelta(days=1))
        alive = self.user.session_set.create(
            session_key='ALIVE', ip='127.0.0.1',
            expire_date=now() + timedelta(days=1))
        batch_id = 'restart-batch'
        from user_sessions.revocation import revoke_sessions

        # First attempt crashes right after deleting GHOST: emulate by
        # deleting the row without any audit event.
        Session.objects.filter(pk=ghost.session_key).delete()
        report = revoke_sessions(
            self.user.session_set.filter(expire_date__gt=now()),
            ['GHOST', 'ALIVE'],
            batch_id=batch_id,
        )
        self.assertEqual(
            report.revoked_session_keys, {'GHOST', 'ALIVE'})
        self.assertFalse(Session.objects.filter(pk=alive.session_key).exists())

    def test_delete_other_writes_itemized_audit_for_every_device(self):
        self.user.session_set.create(
            session_key='AUDITED', ip='127.0.0.1',
            expire_date=now() + timedelta(days=1))
        self.client.post(reverse('user_sessions:session_delete_other'))

        events = SessionRevocationEvent.objects.filter(
            session_key='AUDITED').order_by('id')
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].outcome,
                         SessionRevocationEvent.OUTCOME_REVOKED)
        self.assertIn('deleted', events[0].detail)

    def test_single_delete_partial_failure_reports_failure_location(self):
        other = self.user.session_set.create(
            session_key='BROKEN', ip='127.0.0.1',
            expire_date=now() + timedelta(days=1))
        inject_failure(SessionRevocationEvent.STAGE_COMMIT,
                       'BROKEN', DatabaseError('commit boom'))
        try:
            response = self.client.post(
                reverse('user_sessions:session_delete',
                        args=[other.session_key]))
        finally:
            clear_injected_failures()

        self.assertRedirects(response, reverse('user_sessions:session_list'))
        report = response.revocation_report
        self.assertEqual(report.failed_session_keys, {'BROKEN'})
        self.assertEqual(report.failures[0]['stage'],
                         SessionRevocationEvent.STAGE_COMMIT)
        # The failed device is still active.
        self.assertTrue(
            Session.objects.filter(session_key='BROKEN').exists())

    def test_unknown_session_delete_still_returns_404(self):
        response = self.client.post(
            reverse('user_sessions:session_delete', args=['NO-SUCH-KEY']))
        self.assertEqual(response.status_code, 404)
        self.assertFalse(
            SessionRevocationEvent.objects.filter(
                session_key='NO-SUCH-KEY').exists())
