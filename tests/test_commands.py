from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.core.management import call_command
from django.db import IntegrityError
from django.test import TestCase, TransactionTestCase
from django.test.utils import modify_settings
from django.utils.timezone import now

from user_sessions.models import Session


class ClearsessionsCommandTest(TestCase):
    def test_can_call(self):
        Session.objects.create(expire_date=now() - timedelta(days=1),
                               ip='127.0.0.1')
        call_command('clearsessions')
        self.assertEqual(Session.objects.count(), 0)


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

    @modify_settings(INSTALLED_APPS={'append': 'django.contrib.sessions'})
    def test_migrate_publishes_complete_batches_only(self):
        """
        A failure halfway through the import must not publish a partial
        batch: the conversion is rolled back and can simply be retried.
        """
        from django.contrib.sessions.backends.db import (
            SessionStore as DjangoSessionStore,
        )
        from django.contrib.sessions.models import Session as DjangoSession
        try:
            call_command('migrate', 'sessions')
            user = User.objects.create_user('bouke', '', 'secret')
            for _ in range(2):
                session = DjangoSessionStore()
                session['_auth_user_id'] = user.id
                session.save()
            self.assertEqual(DjangoSession.objects.count(), 2)

            real_get_or_create = Session.objects.get_or_create
            attempts = []

            def fail_second(*args, **kwargs):
                attempts.append(1)
                if len(attempts) > 1:
                    raise IntegrityError("simulated failure halfway through")
                return real_get_or_create(*args, **kwargs)

            with mock.patch.object(Session.objects, 'get_or_create',
                                   side_effect=fail_second):
                with self.assertRaises(IntegrityError):
                    call_command('migratesessions')
            # Nothing was published: the partial batch was rolled back.
            self.assertEqual(Session.objects.count(), 0)

            # A retry without the failure imports the complete batch.
            call_command('migratesessions')
            self.assertEqual(Session.objects.count(), 2)
        finally:
            call_command('migrate', 'sessions', 'zero')

    @modify_settings(INSTALLED_APPS={'append': 'django.contrib.sessions'})
    def test_migrate_leaves_existing_sessions_untouched(self):
        """
        A session that already exists in the new table (e.g. created
        concurrently by a login while the import runs) is left untouched.
        """
        from django.contrib.sessions.backends.db import (
            SessionStore as DjangoSessionStore,
        )
        try:
            call_command('migrate', 'sessions')
            user = User.objects.create_user('bouke', '', 'secret')
            old = DjangoSessionStore()
            old['_auth_user_id'] = user.id
            old.save()
            Session.objects.create(
                session_key=old.session_key,
                session_data=old.session_data,
                expire_date=now() + timedelta(days=1),
                user=user,
                ip='10.0.0.1',
            )
            call_command('migratesessions')
            new_session = Session.objects.get()
            self.assertEqual(new_session.ip, '10.0.0.1')
        finally:
            call_command('migrate', 'sessions', 'zero')

    @modify_settings(INSTALLED_APPS={'append': 'django.contrib.sessions'})
    def test_migrate_legacy_serialized_session(self):
        """
        Sessions serialized with a legacy serializer (e.g. pickle, from
        before SESSION_SERIALIZER was switched to JSON) must remain
        readable: their provenance payload is preserved verbatim and their
        owner is still resolved.
        """
        from django.contrib.sessions.backends.db import (
            SessionStore as DjangoSessionStore,
        )
        from django.contrib.sessions.models import Session as DjangoSession
        from django.contrib.sessions.serializers import PickleSerializer
        try:
            call_command('migrate', 'sessions')
            user = User.objects.create_user('bouke', '', 'secret')
            old = DjangoSessionStore()
            old.serializer = PickleSerializer
            old['_auth_user_id'] = user.id
            old.save()
            old_session = DjangoSession.objects.get(pk=old.session_key)

            call_command('migratesessions')

            new_session = Session.objects.get()
            self.assertEqual(new_session.user, user)
            self.assertEqual(new_session.expire_date, old_session.expire_date)
            # The original payload is preserved verbatim as provenance ...
            self.assertEqual(new_session.session_data, old_session.session_data)
            # ... and remains readable through the session store.
            self.assertEqual(new_session.get_decoded(), {'_auth_user_id': user.id})
        finally:
            call_command('migrate', 'sessions', 'zero')
