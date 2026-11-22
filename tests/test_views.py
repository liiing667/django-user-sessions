from datetime import timedelta
from unittest import mock
import warnings

from django.conf import settings
from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from django.utils.timezone import now

from user_sessions.backends.db import SessionStore

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

    def get_session_list(self):
        """GET the session list, ignoring GeoIP lookup warnings."""
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            return self.client.get(reverse('user_sessions:session_list'))

    def test_list_orders_by_last_activity_and_hides_expired(self):
        """
        The session list is consumed with the same generation marker the
        store writes: most recent activity first, expired sessions hidden.
        """
        reference = now()
        self.user.session_set.create(session_key='OLDER', ip='127.0.0.1',
                                     expire_date=reference + timedelta(days=1),
                                     last_activity=reference - timedelta(days=2),
                                     user_agent='Firefox')
        self.user.session_set.create(session_key='NEWER', ip='127.0.0.1',
                                     expire_date=reference + timedelta(days=1),
                                     last_activity=reference - timedelta(hours=1),
                                     user_agent='Chrome')
        self.user.session_set.create(session_key='EXPIRED', ip='127.0.0.1',
                                     expire_date=reference - timedelta(days=1),
                                     last_activity=reference - timedelta(days=3),
                                     user_agent='Safari')
        response = self.get_session_list()
        self.assertContains(response, 'Chrome')
        self.assertContains(response, 'Firefox')
        self.assertNotContains(response, 'Safari')
        content = response.content.decode()
        self.assertLess(content.index('Chrome'), content.index('Firefox'))

    def test_expired_session_is_not_revived_after_resume(self):
        """
        After a suspend/resume time jump the expired session stays hidden
        from the session list, and a late write from another instance
        cannot make it valid again.
        """
        reference = now()
        self.user.session_set.create(session_key='STALE', ip='127.0.0.1',
                                     expire_date=reference + timedelta(hours=1),
                                     last_activity=reference,
                                     user_agent='Firefox')
        # Another instance loaded the session while it was still valid.
        stale = SessionStore(session_key='STALE', user_agent='Firefox', ip='127.0.0.1')
        stale.load()
        stale['late'] = 'write'

        # While valid, the session is listed.
        response = self.get_session_list()
        self.assertContains(response, 'Firefox')

        # The machine suspends and resumes two hours later.
        resumed_at = reference + timedelta(hours=2)
        with mock.patch('django.utils.timezone.now', return_value=resumed_at):
            response = self.get_session_list()
            self.assertNotContains(response, 'Firefox')

            # The late write must not make the expired session valid again.
            stale.save()
            session = self.user.session_set.get(session_key='STALE')
            self.assertLess(session.expire_date, resumed_at)

            response = self.get_session_list()
            self.assertNotContains(response, 'Firefox')

    def test_delete_some_other(self):
        other = self.user.session_set.create(session_key='OTHER', ip='127.0.0.1',
                                             expire_date=now() + timedelta(days=1))
        self.assertEqual(self.user.session_set.count(), 2)
        response = self.client.post(reverse('user_sessions:session_delete',
                                            args=[other.session_key]))
        with self.assertWarnsRegex(UserWarning, r"The address 127\.0\.0\.1 is not in the database"):
            self.assertRedirects(response, reverse('user_sessions:session_list'))
        self.assertEqual(self.user.session_set.count(), 1)
