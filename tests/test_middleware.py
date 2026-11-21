from django.contrib.auth.models import User
from django.conf import settings
from django.test import TestCase
from django.urls import reverse

from user_sessions.models import Session
from user_sessions.utils import invalidate_user_sessions


class MiddlewareTest(TestCase):
    def test_unmodified_session(self):
        self.client.get('/', HTTP_USER_AGENT='Python/2.7')
        self.assertNotIn(settings.SESSION_COOKIE_NAME, self.client.cookies)

    def test_modify_session(self):
        self.client.get('/modify_session/', HTTP_USER_AGENT='Python/2.7')
        self.assertIn(settings.SESSION_COOKIE_NAME, self.client.cookies)
        session = Session.objects.get(
            pk=self.client.cookies[settings.SESSION_COOKIE_NAME].value
        )
        self.assertEqual(session.user_agent, 'Python/2.7')
        self.assertEqual(session.ip, '127.0.0.1')

    def test_login(self):
        admin_login_url = reverse('admin:login')
        user = User.objects.create_superuser('bouke', '', 'secret')
        response = self.client.post(admin_login_url,
                                    data={
                                        'username': 'bouke',
                                        'password': 'secret',
                                        'this_is_the_login_form': '1',
                                        'next': '/admin/'},
                                    HTTP_USER_AGENT='Python/2.7')
        self.assertRedirects(response, '/admin/')
        session = Session.objects.get(
            pk=self.client.cookies[settings.SESSION_COOKIE_NAME].value
        )
        self.assertEqual(
            self.client.cookies[settings.SESSION_COOKIE_NAME]["samesite"],
            settings.SESSION_COOKIE_SAMESITE,
        )
        self.assertEqual(user, session.user)

    def test_long_ua(self):
        self.client.get('/modify_session/',
                        HTTP_USER_AGENT=''.join('a' for _ in range(400)))

    def test_invalidated_session_is_rejected(self):
        user = User.objects.create_superuser('bouke', '', 'secret')
        self.client.post(reverse('admin:login'),
                         data={
                             'username': 'bouke',
                             'password': 'secret',
                             'this_is_the_login_form': '1',
                             'next': '/admin/'},
                         HTTP_USER_AGENT='Python/2.7')
        session_key = self.client.cookies[settings.SESSION_COOKIE_NAME].value
        response = self.client.get('/admin/', HTTP_USER_AGENT='Python/2.7')
        self.assertEqual(response.status_code, 200)

        invalidate_user_sessions(user)

        # The old session is rejected on the next request: the user is no
        # longer authenticated and the session is removed.
        response = self.client.get('/admin/', HTTP_USER_AGENT='Python/2.7')
        self.assertRedirects(response, '/admin/login/?next=/admin%2F')
        self.assertFalse(Session.objects.filter(pk=session_key).exists())

    def test_invalidate_keeps_current_session(self):
        user = User.objects.create_superuser('bouke', '', 'secret')
        self.client.post(reverse('admin:login'),
                         data={
                             'username': 'bouke',
                             'password': 'secret',
                             'this_is_the_login_form': '1',
                             'next': '/admin/'},
                         HTTP_USER_AGENT='Python/2.7')
        session_key = self.client.cookies[settings.SESSION_COOKIE_NAME].value

        invalidate_user_sessions(user, keep_session_keys=[session_key])

        response = self.client.get('/admin/', HTTP_USER_AGENT='Python/2.7')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(Session.objects.filter(pk=session_key).exists())
