from django.contrib import auth
from django.contrib.auth.models import User
from django.test import TestCase

from user_sessions.backends.db import SessionStore
from user_sessions.models import Session, SessionRevocationEvent


class ModelTest(TestCase):
    def test_get_decoded(self):
        User.objects.create_user('bouke', '', 'secret', id=1)
        store = SessionStore(user_agent='Python/2.7', ip='127.0.0.1')
        store[auth.SESSION_KEY] = 1
        store['foo'] = 'bar'
        store.save()

        session = Session.objects.get(pk=store.session_key)
        self.assertEqual(session.get_decoded(),
                         {'foo': 'bar', auth.SESSION_KEY: 1})

    def test_very_long_ua(self):
        ua = 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; ' \
             'Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; ' \
             '.NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; ' \
             'InfoPath.3; ms-office; MSOffice 14)'
        store = SessionStore(user_agent=ua, ip='127.0.0.1')
        store.save()

        session = Session.objects.get(pk=store.session_key)
        self.assertEqual(session.user_agent, ua[:200])


class SessionRevocationEventModelTest(TestCase):
    def test_outcome_helpers_and_str(self):
        event = SessionRevocationEvent.objects.create(
            batch_id='batch-1',
            session_key='KEY',
            outcome=SessionRevocationEvent.OUTCOME_FAILED,
            stage=SessionRevocationEvent.STAGE_DELETE,
            detail='DatabaseError: boom',
        )
        self.assertTrue(event.is_failed)
        self.assertFalse(event.is_revoked)
        self.assertFalse(event.is_retained)
        text = str(event)
        self.assertIn('KEY', text)
        self.assertIn('failed', text)
        self.assertIn('delete', text)

        event.outcome = SessionRevocationEvent.OUTCOME_REVOKED
        self.assertTrue(event.is_revoked)
        event.outcome = SessionRevocationEvent.OUTCOME_RETAINED
        self.assertTrue(event.is_retained)

    def test_default_detail_is_blank(self):
        event = SessionRevocationEvent.objects.create(
            batch_id='batch-2',
            session_key='KEY',
            outcome=SessionRevocationEvent.OUTCOME_REVOKED,
            stage=SessionRevocationEvent.STAGE_COMMIT,
        )
        self.assertEqual(event.detail, '')
