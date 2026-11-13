import os
import tempfile
import threading
from datetime import timedelta

from django.contrib import auth
from django.contrib.auth.models import User
from django.contrib.sessions.backends.base import CreateError
from django.test import TestCase, TransactionTestCase, override_settings
from django.utils.timezone import now

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


class ActiveSessionLimitTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('bouke', '', 'secret')

    def _create_authenticated_session(self, user=None):
        user_id = (user or self.user).id
        store = SessionStore(user_agent='Python/2.7', ip='127.0.0.1')
        store[auth.SESSION_KEY] = user_id
        store.create()
        return store

    @override_settings(SESSION_ACTIVE_LIMIT=3)
    def test_evicts_oldest_sessions_on_creation(self):
        stores = [self._create_authenticated_session() for _ in range(3)]
        # Force a deterministic ordering of the last_activity timestamps.
        for index, store in enumerate(stores):
            Session.objects.filter(pk=store.session_key).update(
                last_activity=now() - timedelta(days=3 - index))
        self.assertEqual(
            Session.objects.filter(user=self.user).count(), 3)

        newest = self._create_authenticated_session()
        active_keys = set(
            Session.objects.filter(user=self.user)
            .values_list('session_key', flat=True)
        )
        self.assertEqual(len(active_keys), 3)
        self.assertIn(newest.session_key, active_keys)
        # The oldest session is evicted first.
        self.assertNotIn(stores[0].session_key, active_keys)
        self.assertIn(stores[2].session_key, active_keys)

    @override_settings(SESSION_ACTIVE_LIMIT=2)
    def test_never_exceeds_limit(self):
        for _ in range(6):
            self._create_authenticated_session()
        self.assertEqual(Session.objects.filter(user=self.user).count(), 2)

    @override_settings(SESSION_ACTIVE_LIMIT=2)
    def test_anonymous_sessions_are_not_limited(self):
        for _ in range(5):
            store = SessionStore(user_agent='Python/2.7', ip='127.0.0.1')
            store.create()
        self.assertEqual(
            Session.objects.filter(user__isnull=True).count(), 5)

    @override_settings(SESSION_ACTIVE_LIMIT=2)
    def test_limit_is_per_user(self):
        for _ in range(3):
            self._create_authenticated_session()
        user2 = User.objects.create_user('harry', '', 'secret')
        for _ in range(3):
            self._create_authenticated_session(user=user2)
        self.assertEqual(
            Session.objects.filter(user=self.user).count(), 2)
        self.assertEqual(Session.objects.filter(user_id=user2.id).count(), 2)

    @override_settings(SESSION_ACTIVE_LIMIT=2)
    def test_expired_sessions_are_ignored_and_evicted_by_filter(self):
        expired = self._create_authenticated_session()
        Session.objects.filter(pk=expired.session_key).update(
            expire_date=now() - timedelta(days=1))
        active = self._create_authenticated_session()
        self._create_authenticated_session()

        active_rows = Session.objects.filter(
            user=self.user, expire_date__gt=now())
        self.assertEqual(active_rows.count(), 2)
        self.assertIn(active.session_key,
                      active_rows.values_list('session_key', flat=True))
        # The expired row is untouched by eviction but stays filtered out of
        # the active session list.
        self.assertTrue(Session.objects.filter(
            pk=expired.session_key,
            expire_date__lt=now()).exists())

    @override_settings(SESSION_ACTIVE_LIMIT=2)
    def test_updating_existing_session_does_not_evict(self):
        store = self._create_authenticated_session()
        other = self._create_authenticated_session()
        store['FOO'] = 'BAR'
        store.save()
        self.assertEqual(Session.objects.filter(user=self.user).count(), 2)
        self.assertTrue(Session.objects.filter(
            pk__in=[store.session_key, other.session_key]).count(), 2)

    @override_settings(SESSION_ACTIVE_LIMIT=0)
    def test_non_positive_limit_disables_cap(self):
        for _ in range(4):
            self._create_authenticated_session()
        self.assertEqual(Session.objects.filter(user=self.user).count(), 4)

    def test_unconfigured_limit_disables_cap(self):
        for _ in range(4):
            self._create_authenticated_session()
        self.assertEqual(Session.objects.filter(user=self.user).count(), 4)

    @override_settings(SESSION_ACTIVE_LIMIT=2)
    def test_must_create_still_raises_on_duplicate(self):
        store = self._create_authenticated_session()
        duplicate = SessionStore(session_key=store.session_key,
                                 user_agent='Python/2.7', ip='127.0.0.1')
        with self.assertRaises(CreateError):
            duplicate.save(must_create=True)


class AsyncActiveSessionLimitTest(TransactionTestCase):
    @override_settings(SESSION_ACTIVE_LIMIT=2)
    async def test_async_create_respects_limit(self):
        user = await User.objects.acreate(username='bouke', password='secret')
        for _ in range(4):
            store = SessionStore(user_agent='Python/2.7', ip='127.0.0.1')
            store[auth.SESSION_KEY] = user.id
            await store.acreate()
        self.assertEqual(
            await Session.objects.filter(user=user).acount(), 2)

    @override_settings(SESSION_ACTIVE_LIMIT=2)
    async def test_async_anonymous_sessions_are_not_limited(self):
        for _ in range(3):
            store = SessionStore(user_agent='Python/2.7', ip='127.0.0.1')
            await store.acreate()
        self.assertEqual(
            await Session.objects.filter(user__isnull=True).acount(), 3)


class ConcurrentSessionLimitTest(TransactionTestCase):
    """
    Exercise the eviction logic against a real file-based SQLite database so
    that multiple threads (and therefore separate database connections)
    create sessions concurrently.
    """

    def setUp(self):
        from django.conf import settings
        from django.db import connection

        self._threads = threading
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self._original_db_config = dict(settings.DATABASES['default'])
        self.db_path = os.path.join(self.tmpdir.name, 'concurrent.sqlite3')
        settings.DATABASES['default'].update({
            'NAME': self.db_path,
            'OPTIONS': {
                'timeout': 10,
                'init_command': "PRAGMA journal_mode=WAL;",
            },
        })
        connection.close()
        # Build the schema on the file-based database.
        from django.core.management import call_command
        call_command('migrate', verbosity=0, run_syncdb=True)
        self.user = User.objects.create_user('bouke', '', 'secret')

    def tearDown(self):
        from django.conf import settings
        from django.db import connection

        connection.close()
        settings.DATABASES['default'].clear()
        settings.DATABASES['default'].update(self._original_db_config)
        # Reopen the connection against the original (in-memory) test
        # database so Django's test runner can tear it down normally.
        connection.ensure_connection()

    @override_settings(SESSION_ACTIVE_LIMIT=5)
    def test_concurrent_creation_never_exceeds_limit(self):
        errors = []
        thread_count = 20
        barrier = self._threads.Barrier(thread_count)

        def create_session():
            from django.db import OperationalError, connection
            try:
                barrier.wait()
                store = SessionStore(user_agent='Python/2.7',
                                      ip='127.0.0.1')
                store[auth.SESSION_KEY] = self.user.id
                for attempt in range(50):
                    try:
                        store.create()
                        break
                    except OperationalError as exc:
                        last_error = exc
                        connection.close()
                else:  # pragma: no cover - retry path
                    errors.append(last_error)
            except Exception as exc:  # noqa: BLE001 - test failure collector
                errors.append(exc)

        threads = [self._threads.Thread(target=create_session)
                   for _ in range(thread_count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(errors, [])
        active = Session.objects.filter(
            user_id=self.user.id, expire_date__gt=now())
        self.assertEqual(active.count(), 5)
