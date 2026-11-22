from datetime import timedelta

from django.conf import settings
from django.contrib.auth.models import User
from django.test import RequestFactory, TestCase
from django.urls import reverse
from django.utils.timezone import now

from user_sessions.backends.db import SessionStore
from user_sessions.models import Session
from user_sessions.revocation import SessionRevocationReport, revoke_sessions
from user_sessions.views import SessionListView, SessionMixin

from .utils import Client


class ViewsTest(TestCase):
    client_class = Client

    def setUp(self):
        self.user = User.objects.create_user('bouke', '', 'secret')
        assert self.client.login(username='bouke', password='secret')

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


class SessionRevocationViewsTest(TestCase):
    """
    The delete views freeze the requesting user, the current device and
    the target session when the request enters the view, re-check the
    ownership of the frozen selection and classify the outcome as kept /
    revoked / expired.
    """
    client_class = Client

    def setUp(self):
        self.user = User.objects.create_user('bouke', '', 'secret')
        assert self.client.login(username='bouke', password='secret')

    def test_delete_some_other_reports_revoked(self):
        other = self.user.session_set.create(
            session_key='OTHER', ip='127.0.0.1',
            expire_date=now() + timedelta(days=1))
        response = self.client.post(reverse('user_sessions:session_delete',
                                            args=[other.session_key]))
        with self.assertWarnsRegex(UserWarning, r"The address 127\.0\.0\.1 is not in the database"):
            self.assertRedirects(response, reverse('user_sessions:session_list'))
        report = response.revocation_report
        self.assertEqual(report.revoked_session_keys, {'OTHER'})
        self.assertEqual(report.kept_session_keys, set())
        self.assertEqual(report.expired_session_keys, set())
        self.assertFalse(Session.objects.filter(session_key='OTHER').exists())

    def test_delete_current_device_logs_out_and_reports(self):
        session_key = self.client.cookies[settings.SESSION_COOKIE_NAME].value
        response = self.client.post(reverse('user_sessions:session_delete',
                                            args=[session_key]))
        self.assertRedirects(response, '/')
        self.assertEqual(response.revocation_report.revoked_session_keys,
                         {session_key})
        self.assertFalse(Session.objects.filter(session_key=session_key).exists())

    def test_delete_other_keeps_current_anonymous_and_foreign(self):
        other_user = User.objects.create_user('alice', '', 'secret')
        self.user.session_set.create(session_key='OTHER-DEVICE', ip='127.0.0.1',
                                     expire_date=now() + timedelta(days=1))
        self.user.session_set.create(session_key='EXPIRED', ip='127.0.0.1',
                                     expire_date=now() - timedelta(days=1))
        Session.objects.create(session_key='ANONYMOUS', ip='127.0.0.1',
                               expire_date=now() + timedelta(days=1))
        other_user.session_set.create(session_key='FOREIGN', ip='127.0.0.1',
                                      expire_date=now() + timedelta(days=1))
        current = self.client.cookies[settings.SESSION_COOKIE_NAME].value

        response = self.client.post(reverse('user_sessions:session_delete_other'))
        with self.assertWarnsRegex(UserWarning, r"The address 127\.0\.0\.1 is not in the database"):
            self.assertRedirects(response, reverse('user_sessions:session_list'))

        # Only the other active device of the user was revoked; the current
        # device, the anonymous session, the foreign session and even the
        # expired session are all preserved.
        remaining = set(Session.objects.values_list('session_key', flat=True))
        self.assertEqual(remaining, {current, 'EXPIRED', 'ANONYMOUS', 'FOREIGN'})

        # The report shows the three categories: kept / revoked / expired.
        report = response.revocation_report
        self.assertEqual(report.kept_session_keys, {current})
        self.assertEqual(report.revoked_session_keys, {'OTHER-DEVICE'})
        self.assertEqual(report.expired_session_keys, {'EXPIRED'})
        self.assertEqual(report.summary, {'kept': 1, 'revoked': 1, 'expired': 1})

    def test_delete_foreign_session_returns_404(self):
        other_user = User.objects.create_user('alice', '', 'secret')
        other_user.session_set.create(session_key='FOREIGN', ip='127.0.0.1',
                                      expire_date=now() + timedelta(days=1))
        response = self.client.post(reverse('user_sessions:session_delete',
                                            args=['FOREIGN']))
        self.assertEqual(response.status_code, 404)
        self.assertTrue(Session.objects.filter(session_key='FOREIGN').exists())

    def test_delete_expired_session_returns_404(self):
        self.user.session_set.create(session_key='EXPIRED', ip='127.0.0.1',
                                     expire_date=now() - timedelta(days=1))
        response = self.client.post(reverse('user_sessions:session_delete',
                                            args=['EXPIRED']))
        self.assertEqual(response.status_code, 404)
        self.assertTrue(Session.objects.filter(session_key='EXPIRED').exists())

    def test_delete_anonymous_session_returns_404(self):
        Session.objects.create(session_key='ANONYMOUS', ip='127.0.0.1',
                               expire_date=now() + timedelta(days=1))
        response = self.client.post(reverse('user_sessions:session_delete',
                                            args=['ANONYMOUS']))
        self.assertEqual(response.status_code, 404)
        self.assertTrue(Session.objects.filter(session_key='ANONYMOUS').exists())


class RevokeSessionsTest(TestCase):
    """
    The revocation service re-checks ownership against the frozen user and
    classifies every submitted session key as kept / revoked / expired.
    """
    def setUp(self):
        self.user = User.objects.create_user('bouke', '', 'secret')

    def test_classifies_kept_revoked_expired(self):
        other_user = User.objects.create_user('alice', '', 'secret')
        self.user.session_set.create(session_key='REVOKE', ip='127.0.0.1',
                                     expire_date=now() + timedelta(days=1))
        self.user.session_set.create(session_key='EXPIRED', ip='127.0.0.1',
                                     expire_date=now() - timedelta(days=1))
        Session.objects.create(session_key='ANONYMOUS', ip='127.0.0.1',
                               expire_date=now() + timedelta(days=1))
        other_user.session_set.create(session_key='FOREIGN', ip='127.0.0.1',
                                      expire_date=now() + timedelta(days=1))

        report = revoke_sessions(
            self.user,
            ['CURRENT', 'REVOKE', 'EXPIRED', 'ANONYMOUS', 'FOREIGN', 'UNKNOWN'],
            current_session_key='CURRENT',
        )

        self.assertEqual(report.kept_session_keys,
                         {'CURRENT', 'ANONYMOUS', 'FOREIGN', 'UNKNOWN'})
        self.assertEqual(report.revoked_session_keys, {'REVOKE'})
        self.assertEqual(report.expired_session_keys, {'EXPIRED'})
        self.assertEqual(report.session_keys,
                         {'CURRENT', 'REVOKE', 'EXPIRED', 'ANONYMOUS',
                          'FOREIGN', 'UNKNOWN'})
        self.assertEqual(
            report,
            SessionRevocationReport(
                kept={'CURRENT', 'ANONYMOUS', 'FOREIGN', 'UNKNOWN'},
                revoked={'REVOKE'},
                expired={'EXPIRED'},
            ),
        )

        # Only the user's own active session was deleted.
        remaining = set(Session.objects.values_list('session_key', flat=True))
        self.assertEqual(remaining, {'EXPIRED', 'ANONYMOUS', 'FOREIGN'})

    def test_revoke_sessions_is_deterministic_for_same_identity(self):
        self.user.session_set.create(session_key='REVOKE', ip='127.0.0.1',
                                     expire_date=now() + timedelta(days=1))
        first = revoke_sessions(self.user, ['CURRENT', 'REVOKE'],
                                current_session_key='CURRENT')
        # A consumer reclassifying the same frozen identity after the
        # deletion (e.g. after a restart) never touches the current device
        # and never raises for the already-revoked key.
        second = revoke_sessions(self.user, ['CURRENT', 'REVOKE'],
                                 current_session_key='CURRENT')
        self.assertEqual(first.revoked_session_keys, {'REVOKE'})
        self.assertEqual(second.kept_session_keys, {'CURRENT', 'REVOKE'})
        self.assertEqual(second.revoked_session_keys, set())


class FrozenIdentityTest(TestCase):
    """
    The list selection freezes the requesting user, the current device and
    the target session as soon as the request enters the view.
    """
    def setUp(self):
        self.user = User.objects.create_user('bouke', '', 'secret')

    def make_view(self, view_class=None):
        class TerminalView:
            def dispatch(self, request, *args, **kwargs):
                return 'OK'

        class FrozenView(SessionMixin, TerminalView):
            pass

        return FrozenView()

    def make_request(self, session_key='CURRENT-KEY'):
        request = RequestFactory().get(reverse('user_sessions:session_list'))
        request.user = self.user
        request.session = SessionStore(session_key=session_key,
                                       user_agent='Python/2.7', ip='127.0.0.1')
        return request

    def test_dispatch_freezes_request_identity(self):
        view = self.make_view()
        request = self.make_request()
        view.dispatch(request, pk='TARGET-KEY')

        self.assertEqual(view.request_user, self.user)
        self.assertEqual(view.current_session_key, 'CURRENT-KEY')
        self.assertEqual(view.target_session_key, 'TARGET-KEY')

    def test_frozen_identity_survives_request_switch(self):
        other_user = User.objects.create_user('alice', '', 'secret')
        self.user.session_set.create(session_key='MINE', ip='127.0.0.1',
                                     expire_date=now() + timedelta(days=1))
        other_user.session_set.create(session_key='THEIRS', ip='127.0.0.1',
                                      expire_date=now() + timedelta(days=1))
        view = self.make_view()
        request = self.make_request()
        view.dispatch(request, pk='TARGET-KEY')

        # Another request re-authenticates this very request object and
        # rotates the session key: the frozen identity must not follow.
        request.user = other_user
        request.session.session_key = 'HIJACKED-KEY'

        self.assertEqual(
            list(view.get_queryset().values_list('session_key', flat=True)),
            ['MINE'],
        )
        self.assertEqual(view.get_current_session_key(), 'CURRENT-KEY')
        self.assertEqual(view.get_target_session_key(), 'TARGET-KEY')

    def test_old_callers_without_dispatch_get_original_results(self):
        self.user.session_set.create(session_key='MINE', ip='127.0.0.1',
                                     expire_date=now() + timedelta(days=1))
        request = self.make_request()
        view = SessionListView()
        view.request = request
        view.kwargs = {}

        self.assertEqual(
            list(view.get_queryset().values_list('session_key', flat=True)),
            ['MINE'],
        )
        self.assertEqual(view.get_current_session_key(), 'CURRENT-KEY')
        self.assertIsNone(view.get_target_session_key())
