from unittest.mock import patch

from django.contrib import auth
from django.contrib.auth.models import User
from django.conf import settings
from django.test import TestCase
from django.test.utils import override_settings
from django.urls import reverse

from user_sessions.backends.db import SessionStore
from user_sessions.models import Session, SessionRotation

from .utils import Client


class ClientTest(TestCase):
    def test_invalid_login(self):
        client = Client()
        self.assertFalse(client.login())

    def test_restore_session(self):
        store = SessionStore(user_agent='Python/2.7', ip='127.0.0.1')
        store['foo'] = 'bar'
        store.save()
        client = Client()
        client.cookies[settings.SESSION_COOKIE_NAME] = store.session_key
        User.objects.create_user('bouke', '', 'secret')
        assert client.login(username='bouke', password='secret')
        self.assertEqual(client.session['foo'], 'bar')

    def test_login_logout(self):
        client = Client()
        User.objects.create_user('bouke', '', 'secret')
        assert client.login(username='bouke', password='secret')
        assert settings.SESSION_COOKIE_NAME in client.cookies

        client.logout()
        assert settings.SESSION_COOKIE_NAME not in client.cookies

        # should not raise
        client.logout()

    @patch('django.contrib.auth.signals.user_logged_in.send')
    def test_login_signal(self, mock_user_logged_in):
        client = Client()
        User.objects.create_user('bouke', '', 'secret')
        assert client.login(username='bouke', password='secret')
        assert mock_user_logged_in.called
        request = mock_user_logged_in.call_args[1]['request']
        assert getattr(request, 'user', None) is not None

    @override_settings(INSTALLED_APPS=())
    def test_no_session(self):
        self.assertIsNone(Client().session)

    def test_anonymous_migration_and_logout_are_terminal(self):
        anonymous = SessionStore(user_agent='Python/2.7', ip='127.0.0.1')
        anonymous['cart'] = 'apple'
        anonymous.save()
        old_key = anonymous.session_key

        client = Client()
        client.cookies[settings.SESSION_COOKIE_NAME] = old_key
        User.objects.create_user('bouke', '', 'secret')
        self.assertTrue(client.login(username='bouke', password='secret'))
        new_key = client.cookies[settings.SESSION_COOKIE_NAME].value

        self.assertNotEqual(old_key, new_key)
        self.assertEqual(client.session['cart'], 'apple')
        self.assertFalse(Session.objects.filter(pk=old_key).exists())

        client.logout()
        self.assertFalse(Session.objects.filter(pk=new_key).exists())
        self.assertEqual(SessionStore(session_key=old_key).load(), {})

        stale = SessionStore(session_key=old_key)
        stale['late'] = True
        stale.save()
        self.assertFalse(Session.objects.filter(pk=old_key).exists())

    def test_delete_current_session_view_revokes_old_anonymous_key(self):
        anonymous = SessionStore(user_agent='Python/2.7', ip='127.0.0.1')
        anonymous['cart'] = 'apple'
        anonymous.save()
        old_key = anonymous.session_key

        client = Client()
        client.cookies[settings.SESSION_COOKIE_NAME] = old_key
        User.objects.create_user('bouke', '', 'secret')
        self.assertTrue(client.login(username='bouke', password='secret'))
        new_key = client.cookies[settings.SESSION_COOKIE_NAME].value

        response = client.post(
            reverse('user_sessions:session_delete', args=[new_key]),
        )
        self.assertRedirects(response, '/')
        self.assertFalse(Session.objects.filter(pk=new_key).exists())
        self.assertEqual(SessionStore(session_key=old_key).load(), {})

    def test_delete_other_session_view_revokes_its_old_key(self):
        user = User.objects.create_user('bouke', '', 'secret')
        client = Client()
        self.assertTrue(client.login(username='bouke', password='secret'))
        current_key = client.cookies[settings.SESSION_COOKIE_NAME].value

        other = SessionStore(user_agent='Python/2.7', ip='127.0.0.1')
        other['other'] = True
        other.save()
        other_old_key = other.session_key
        other[auth.SESSION_KEY] = user.pk
        other.cycle_key()
        other.save()
        other_key = other.session_key

        response = client.post(reverse('user_sessions:session_delete_other'))
        self.assertRedirects(
            response, reverse('user_sessions:session_list'),
        )
        self.assertTrue(Session.objects.filter(pk=current_key).exists())
        self.assertFalse(Session.objects.filter(pk=other_key).exists())
        rotation = SessionRotation.objects.get(pk=other_old_key)
        self.assertEqual(rotation.outcome, SessionRotation.OUTCOME_REVOKED)
        self.assertEqual(SessionStore(session_key=other_old_key).load(), {})
