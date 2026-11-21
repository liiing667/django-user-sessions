from datetime import timedelta

from django.contrib.auth.models import User
from django.db import DatabaseError
from django.test import TestCase
from django.utils.timezone import now

from user_sessions.models import Session, SessionRevocationEvent
from user_sessions.revocation import (
    SessionRevocationReport,
    clear_injected_failures,
    inject_failure,
    revoke_sessions,
)


class RevocationServiceTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('bouke', '', 'secret')
        self.other_user = User.objects.create_user('harry', '', 'secret')
        self.keys = ['DEVICE-A', 'DEVICE-B', 'DEVICE-C', 'DEVICE-D']
        for key in self.keys:
            Session.objects.create(
                session_key=key,
                expire_date=now() + timedelta(days=1),
                user=self.user,
                ip='127.0.0.1',
            )

    def tearDown(self):
        clear_injected_failures()

    def active_queryset(self):
        # Same scoping as the views: owner-filtered and expiry-aware.
        return self.user.session_set.filter(expire_date__gt=now())

    def test_full_success_is_deterministic_and_audited(self):
        report = revoke_sessions(self.active_queryset(), self.keys)

        self.assertEqual(report.revoked_session_keys, set(self.keys))
        self.assertEqual(report.retained_session_keys, set())
        self.assertEqual(report.failed_session_keys, set())
        self.assertEqual(Session.objects.count(), 0)
        self.assertEqual(
            SessionRevocationEvent.objects.filter(
                outcome=SessionRevocationEvent.OUTCOME_REVOKED,
            ).count(),
            len(self.keys),
        )

        # Every device has an itemized audit explanation.
        for key in self.keys:
            events = report.events_for(key)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].outcome,
                             SessionRevocationEvent.OUTCOME_REVOKED)
            self.assertEqual(events[0].stage,
                             SessionRevocationEvent.STAGE_COMMIT)
            self.assertIn('deleted', events[0].detail)

    def test_partial_failure_keeps_an_exact_revoked_and_retained_set(self):
        # DEVICE-B fails at the delete stage; DEVICE-D fails at commit stage.
        inject_failure(SessionRevocationEvent.STAGE_DELETE,
                       'DEVICE-B', DatabaseError('disk full'))
        inject_failure(SessionRevocationEvent.STAGE_COMMIT,
                       'DEVICE-D', DatabaseError('commit crashed'))

        report = revoke_sessions(self.active_queryset(), self.keys)

        # The two healthy devices are revoked, the two broken devices keep
        # their data and are reported as failed (still retained in practice).
        self.assertEqual(report.revoked_session_keys,
                         {'DEVICE-A', 'DEVICE-C'})
        self.assertEqual(report.failed_session_keys,
                         {'DEVICE-B', 'DEVICE-D'})
        self.assertEqual(report.retained_session_keys, set())
        self.assertEqual(
            set(Session.objects.values_list('session_key', flat=True)),
            {'DEVICE-B', 'DEVICE-D'},
        )

        # The report must name the precise failing device AND stage.
        failures = sorted(report.failures, key=lambda f: f['session_key'])
        self.assertEqual(failures, [
            {
                'session_key': 'DEVICE-B',
                'stage': SessionRevocationEvent.STAGE_DELETE,
                'detail': 'DatabaseError: disk full',
            },
            {
                'session_key': 'DEVICE-D',
                'stage': SessionRevocationEvent.STAGE_COMMIT,
                'detail': 'DatabaseError: commit crashed',
            },
        ])
        self.assertFalse(report.summary['complete'])

        # Failed devices have itemized audit rows explaining the stage.
        b_event = report.outcome_of('DEVICE-B')
        self.assertEqual(b_event.outcome,
                         SessionRevocationEvent.OUTCOME_FAILED)
        self.assertEqual(b_event.stage,
                         SessionRevocationEvent.STAGE_DELETE)

    def test_retry_is_idempotent_and_converges_on_the_same_sets(self):
        inject_failure(SessionRevocationEvent.STAGE_DELETE,
                       'DEVICE-B', DatabaseError('disk full'))
        first = revoke_sessions(self.active_queryset(), self.keys,
                                batch_id='BATCH-1')
        self.assertEqual(first.failed_session_keys, {'DEVICE-B'})
        self.assertEqual(first.revoked_session_keys,
                         {'DEVICE-A', 'DEVICE-C', 'DEVICE-D'})

        # Retry the same batch after the underlying problem is repaired.
        clear_injected_failures()
        second = revoke_sessions(self.active_queryset(), self.keys,
                                 batch_id='BATCH-1')

        self.assertEqual(second.revoked_session_keys, set(self.keys))
        self.assertEqual(second.failed_session_keys, set())
        self.assertEqual(Session.objects.count(), 0)

        # DEVICE-B now carries its full history: failed then revoked.
        b_events = second.events_for('DEVICE-B')
        self.assertEqual([e.outcome for e in b_events],
                         [SessionRevocationEvent.OUTCOME_FAILED,
                          SessionRevocationEvent.OUTCOME_REVOKED])
        # The already-revoked devices were not deleted a second time.
        for key in ('DEVICE-A', 'DEVICE-C', 'DEVICE-D'):
            self.assertEqual(len(second.events_for(key)), 1)

        # A report rebuilt fresh (e.g. in a new process) sees the same sets.
        rebuilt = SessionRevocationReport('BATCH-1')
        self.assertEqual(rebuilt.revoked_session_keys,
                         second.revoked_session_keys)
        self.assertEqual(rebuilt.failed_session_keys, set())

    def test_restart_reconciles_rows_deleted_without_an_audit_row(self):
        # Simulate a crash between the committed DELETE and writing the
        # "revoked" audit row for DEVICE-A: the row is simply gone.
        Session.objects.filter(session_key='DEVICE-A').delete()

        report = revoke_sessions(self.active_queryset(), self.keys,
                                batch_id='BATCH-RESTART')

        self.assertEqual(report.revoked_session_keys, set(self.keys))
        self.assertEqual(report.failed_session_keys, set())
        reconciled = report.outcome_of('DEVICE-A')
        self.assertEqual(reconciled.outcome,
                         SessionRevocationEvent.OUTCOME_REVOKED)
        self.assertEqual(reconciled.stage,
                         SessionRevocationEvent.STAGE_QUERY)
        self.assertIn('reconciled as revoked', reconciled.detail)

    def test_query_stage_failure_is_reported_at_the_query_stage(self):
        inject_failure(SessionRevocationEvent.STAGE_QUERY,
                       'DEVICE-B', DatabaseError('connection lost'))

        report = revoke_sessions(self.active_queryset(), self.keys)

        self.assertEqual(report.failed_session_keys, {'DEVICE-B'})
        self.assertEqual(report.failures[0]['stage'],
                         SessionRevocationEvent.STAGE_QUERY)
        self.assertIn('connection lost', report.failures[0]['detail'])
        # Other devices in the same batch were not affected.
        self.assertEqual(
            report.revoked_session_keys,
            {'DEVICE-A', 'DEVICE-C', 'DEVICE-D'},
        )
        self.assertTrue(
            Session.objects.filter(session_key='DEVICE-B').exists()
        )

    def test_current_session_is_retained_and_never_deleted(self):
        report = revoke_sessions(
            self.active_queryset(),
            self.keys,
            current_session_key='DEVICE-B',
        )

        self.assertEqual(report.retained_session_keys, {'DEVICE-B'})
        self.assertEqual(
            report.revoked_session_keys,
            {'DEVICE-A', 'DEVICE-C', 'DEVICE-D'},
        )
        self.assertTrue(
            Session.objects.filter(session_key='DEVICE-B').exists()
        )
        retained = report.outcome_of('DEVICE-B')
        self.assertEqual(retained.outcome,
                         SessionRevocationEvent.OUTCOME_RETAINED)
        self.assertEqual(retained.stage,
                         SessionRevocationEvent.STAGE_QUERY)

    def test_foreign_and_expired_sessions_are_outside_the_queryset(self):
        # A session of another user and an expired session of this user must
        # be reported as revoked-by-reconciliation only if explicitly named;
        # the views simply never pass their keys (queryset-scoped listing).
        Session.objects.create(
            session_key='FOREIGN',
            expire_date=now() + timedelta(days=1),
            user=self.other_user,
            ip='10.0.0.1',
        )
        Session.objects.create(
            session_key='EXPIRED',
            expire_date=now() - timedelta(days=1),
            user=self.user,
            ip='10.0.0.2',
        )

        report = revoke_sessions(
            self.active_queryset(),
            self.keys + ['FOREIGN', 'EXPIRED'],
        )

        # Neither row is reachable through the scoped queryset, so neither
        # can be deleted — and the foreign session row must survive.
        self.assertTrue(
            Session.objects.filter(session_key='FOREIGN').exists()
        )
        self.assertTrue(
            Session.objects.filter(session_key='EXPIRED').exists()
        )
        self.assertEqual(
            report.outcome_of('FOREIGN').stage,
            SessionRevocationEvent.STAGE_QUERY,
        )

    def test_duplicate_keys_are_processed_once(self):
        report = revoke_sessions(
            self.active_queryset(),
            ['DEVICE-A', 'DEVICE-A', 'DEVICE-B'],
        )
        self.assertEqual(report.session_keys, {'DEVICE-A', 'DEVICE-B'})
        self.assertEqual(
            SessionRevocationEvent.objects.filter(
                session_key='DEVICE-A'
            ).count(),
            1,
        )

    def test_report_summary_and_repr(self):
        inject_failure(SessionRevocationEvent.STAGE_DELETE,
                       'DEVICE-B', DatabaseError('nope'))
        report = revoke_sessions(self.active_queryset(), self.keys)
        self.assertEqual(report.summary, {
            'batch_id': report.batch_id,
            'total': 4,
            'revoked': 3,
            'retained': 0,
            'failed': 1,
            'complete': False,
        })
        self.assertIn('failed=1', repr(report))
