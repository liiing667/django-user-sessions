from datetime import timedelta
from unittest.mock import patch

from django.contrib import auth
from django.contrib.auth.models import User
from django.contrib.sessions.backends.base import CreateError
from django.db import DatabaseError
from django.test import TestCase
from django.test.utils import override_settings
from django.utils.timezone import now

from user_sessions.backends.db import SessionStore
from user_sessions.models import Session, SessionRotation


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


class SessionRotationTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('bouke', '', 'secret')

    def anonymous_store(self):
        store = SessionStore(user_agent='Python/2.7', ip='127.0.0.1')
        store['cart'] = 'apple'
        store.save()
        return store

    def test_login_rotation_migrates_anonymous_data_in_one_record(self):
        store = self.anonymous_store()
        old_key = store.session_key

        store[auth.SESSION_KEY] = self.user.pk
        store.cycle_key()
        store.save()
        new_key = store.session_key

        self.assertNotEqual(old_key, new_key)
        self.assertFalse(Session.objects.filter(pk=old_key).exists())

        session = Session.objects.get(pk=new_key)
        self.assertEqual(session.user, self.user)
        self.assertGreater(session.user_version, 0)

        reloaded = SessionStore(session_key=new_key)
        self.assertEqual(reloaded['cart'], 'apple')
        self.assertEqual(
            reloaded.rotation_report()['old_session_key'], old_key,
        )

        rotation = SessionRotation.objects.get(pk=old_key)
        self.assertEqual(rotation.new_session_key, new_key)
        self.assertEqual(rotation.user, self.user)
        self.assertEqual(rotation.user_version, session.user_version)
        self.assertEqual(rotation.outcome, SessionRotation.OUTCOME_ACCEPTED)
        self.assertEqual(rotation.stage, SessionRotation.STAGE_COMMIT)

    def test_stale_save_cannot_recreate_rotated_key(self):
        store = self.anonymous_store()
        old_key = store.session_key

        stale = SessionStore(
            session_key=old_key, user_agent='Python/2.7', ip='127.0.0.1',
        )
        self.assertEqual(stale.load(), {'cart': 'apple'})

        store[auth.SESSION_KEY] = self.user.pk
        store.cycle_key()
        store.save()
        new_key = store.session_key

        stale['late'] = True
        stale.save()

        self.assertFalse(Session.objects.filter(pk=old_key).exists())
        self.assertEqual(stale.session_key, new_key)
        self.assertEqual(
            stale.rejection_phase, SessionRotation.STAGE_LATE_SAVE,
        )
        self.assertNotIn('late', SessionStore(session_key=new_key))
        rotation = SessionRotation.objects.get(pk=old_key)
        self.assertEqual(rotation.new_session_key, new_key)
        self.assertEqual(rotation.user, self.user)
        self.assertEqual(rotation.outcome, SessionRotation.OUTCOME_REJECTED)
        self.assertEqual(
            rotation.rejection_phase, SessionRotation.STAGE_LATE_SAVE,
        )

    def test_concurrent_rotation_has_one_winner(self):
        store = self.anonymous_store()
        old_key = store.session_key

        first = SessionStore(
            session_key=old_key, user_agent='Python/2.7', ip='127.0.0.1',
        )
        second = SessionStore(
            session_key=old_key, user_agent='Python/2.7', ip='127.0.0.1',
        )
        first.load()
        second.load()
        for candidate in (first, second):
            candidate[auth.SESSION_KEY] = self.user.pk
            candidate.cycle_key()

        first.save()
        second.save()

        sessions = Session.objects.filter(user=self.user)
        self.assertEqual(sessions.count(), 1)
        winner = sessions.get()
        self.assertIn(winner.session_key, {first.session_key, second.session_key})
        self.assertFalse(Session.objects.filter(pk=old_key).exists())

        rotation = SessionRotation.objects.get(pk=old_key)
        self.assertEqual(rotation.new_session_key, winner.session_key)
        self.assertEqual(rotation.user, self.user)
        self.assertEqual(rotation.outcome, SessionRotation.OUTCOME_ACCEPTED)
        self.assertEqual(
            rotation.rejection_phase, SessionRotation.STAGE_CONCURRENT,
        )

        mapped = SessionStore(
            session_key=old_key, user_agent='Python/2.7', ip='127.0.0.1',
        )
        self.assertEqual(mapped.load()[auth.SESSION_KEY], self.user.pk)
        self.assertEqual(mapped.session_key, winner.session_key)

    def test_mapped_old_key_aliases_the_live_key(self):
        store = self.anonymous_store()
        old_key = store.session_key
        store[auth.SESSION_KEY] = self.user.pk
        store.cycle_key()
        store.save()
        first_new_key = store.session_key

        mapped = SessionStore(
            session_key=old_key, user_agent='Python/2.7', ip='127.0.0.1',
        )
        data = mapped.load()
        self.assertEqual(data['cart'], 'apple')
        self.assertEqual(data[auth.SESSION_KEY], self.user.pk)
        self.assertEqual(mapped.session_key, first_new_key)
        mapped.save()

        self.assertTrue(Session.objects.filter(pk=first_new_key).exists())
        self.assertFalse(Session.objects.filter(pk=old_key).exists())
        self.assertEqual(
            SessionRotation.objects.get(pk=old_key).new_session_key,
            first_new_key,
        )
        self.assertEqual(
            SessionStore(session_key=first_new_key)['cart'], 'apple',
        )

    def test_direct_save_of_old_key_does_not_overwrite_login_context(self):
        store = self.anonymous_store()
        old_key = store.session_key
        store[auth.SESSION_KEY] = self.user.pk
        store.cycle_key()
        store.save()
        new_key = store.session_key
        before = Session.objects.get(pk=new_key)

        stale = SessionStore(
            session_key=old_key, user_agent='stale-agent', ip='8.8.8.8',
        )
        stale.save()

        after = Session.objects.get(pk=new_key)
        self.assertEqual(stale.session_key, new_key)
        self.assertEqual(after.user_agent, before.user_agent)
        self.assertEqual(after.ip, before.ip)
        self.assertEqual(after.session_data, before.session_data)
        self.assertEqual(after.user, self.user)
        self.assertFalse(Session.objects.filter(pk=old_key).exists())

    def test_write_through_old_key_keeps_the_login_key(self):
        store = self.anonymous_store()
        old_key = store.session_key
        store[auth.SESSION_KEY] = self.user.pk
        store.cycle_key()
        store.save()
        first_new_key = store.session_key

        late = SessionStore(
            session_key=old_key, user_agent='Python/2.7', ip='127.0.0.1',
        )
        late['late'] = True
        late.save()

        self.assertFalse(Session.objects.filter(pk=old_key).exists())
        self.assertTrue(Session.objects.filter(pk=first_new_key).exists())
        self.assertEqual(late.session_key, first_new_key)
        self.assertNotIn('late', SessionStore(session_key=first_new_key))
        self.assertEqual(
            Session.objects.get(pk=first_new_key).user, self.user,
        )
        self.assertEqual(
            SessionRotation.objects.get(pk=old_key).new_session_key,
            first_new_key,
        )
        self.assertEqual(
            SessionRotation.objects.get(pk=old_key).rejection_phase,
            SessionRotation.STAGE_LATE_SAVE,
        )

    def test_mapped_anonymous_old_key_is_re_signed(self):
        store = self.anonymous_store()
        old_key = store.session_key
        store.cycle_key()
        store.save()
        first_new_key = store.session_key

        mapped = SessionStore(
            session_key=old_key, user_agent='Python/2.7', ip='127.0.0.1',
        )
        self.assertEqual(mapped.load(), {'cart': 'apple'})
        resigned_key = mapped.session_key
        self.assertNotIn(resigned_key, {old_key, first_new_key})
        mapped.save()

        self.assertFalse(Session.objects.filter(pk=first_new_key).exists())
        self.assertTrue(Session.objects.filter(pk=resigned_key).exists())

    def test_mapped_old_key_cannot_survive_concurrent_logout(self):
        store = self.anonymous_store()
        old_key = store.session_key
        store[auth.SESSION_KEY] = self.user.pk
        store.cycle_key()
        store.save()
        new_key = store.session_key

        mapped = SessionStore(
            session_key=old_key, user_agent='Python/2.7', ip='127.0.0.1',
        )
        self.assertEqual(mapped.load()[auth.SESSION_KEY], self.user.pk)

        SessionStore(session_key=new_key).flush()
        mapped['late'] = True
        mapped.save()

        self.assertFalse(Session.objects.filter(pk=old_key).exists())
        self.assertFalse(Session.objects.filter(pk=new_key).exists())
        self.assertFalse(mapped.session_key)
        rotation = SessionRotation.objects.get(pk=old_key)
        self.assertEqual(rotation.outcome, SessionRotation.OUTCOME_REVOKED)
        self.assertEqual(
            rotation.rejection_phase, SessionRotation.STAGE_LOGOUT,
        )

    def test_logout_with_a_stale_prelogin_store_revokes_the_login_key(self):
        store = self.anonymous_store()
        old_key = store.session_key
        stale = SessionStore(
            session_key=old_key, user_agent='Python/2.7', ip='127.0.0.1',
        )
        self.assertEqual(stale.load(), {'cart': 'apple'})

        store[auth.SESSION_KEY] = self.user.pk
        store.cycle_key()
        store.save()
        new_key = store.session_key

        stale.flush()
        self.assertFalse(Session.objects.filter(pk=old_key).exists())
        self.assertFalse(Session.objects.filter(pk=new_key).exists())
        self.assertEqual(
            SessionRotation.objects.get(pk=old_key).outcome,
            SessionRotation.OUTCOME_REVOKED,
        )

    def test_rejected_old_mapping_is_not_revived_by_later_rotation(self):
        store = self.anonymous_store()
        old_key = store.session_key
        store[auth.SESSION_KEY] = self.user.pk
        store.cycle_key()
        store.save()
        authenticated_key = store.session_key

        stale = SessionStore(
            session_key=old_key, user_agent='Python/2.7', ip='127.0.0.1',
        )
        stale['stale'] = True
        stale.save()
        self.assertEqual(
            SessionRotation.objects.get(pk=old_key).outcome,
            SessionRotation.OUTCOME_REJECTED,
        )

        current = SessionStore(
            session_key=authenticated_key, user_agent='Python/2.7',
            ip='127.0.0.1',
        )
        current.cycle_key()
        current.save()

        rotation = SessionRotation.objects.get(pk=old_key)
        self.assertEqual(rotation.outcome, SessionRotation.OUTCOME_REJECTED)
        self.assertEqual(SessionStore(session_key=old_key).load(), {})
        self.assertFalse(Session.objects.filter(pk=old_key).exists())

    def test_mapped_old_key_follows_a_later_rotation(self):
        store = self.anonymous_store()
        old_key = store.session_key
        store[auth.SESSION_KEY] = self.user.pk
        store.cycle_key()
        store.save()
        first_new_key = store.session_key

        mapped = SessionStore(
            session_key=old_key, user_agent='Python/2.7', ip='127.0.0.1',
        )
        self.assertEqual(mapped.load()[auth.SESSION_KEY], self.user.pk)

        current = SessionStore(
            session_key=first_new_key, user_agent='Python/2.7',
            ip='127.0.0.1',
        )
        current.cycle_key()
        current.save()
        second_new_key = current.session_key
        self.assertNotEqual(second_new_key, first_new_key)

        mapped.save()
        self.assertEqual(mapped.session_key, second_new_key)
        self.assertEqual(
            SessionRotation.objects.get(pk=old_key).new_session_key,
            second_new_key,
        )
        self.assertEqual(
            SessionStore(session_key=second_new_key)[auth.SESSION_KEY],
            self.user.pk,
        )

    def test_expiry_cleanup_revokes_the_old_mapping(self):
        store = self.anonymous_store()
        old_key = store.session_key
        store[auth.SESSION_KEY] = self.user.pk
        store.cycle_key()
        store.save()
        new_key = store.session_key

        Session.objects.filter(pk=new_key).update(
            expire_date=now() - timedelta(seconds=1),
        )
        SessionStore.clear_expired()

        rotation = SessionRotation.objects.get(pk=old_key)
        self.assertEqual(rotation.outcome, SessionRotation.OUTCOME_REVOKED)
        self.assertEqual(
            rotation.rejection_phase, SessionRotation.STAGE_EXPIRED,
        )
        self.assertEqual(SessionStore(session_key=old_key).load(), {})

    @override_settings(SESSION_ROTATION_GRACE_SECONDS=0)
    def test_old_key_is_rejected_outside_explicit_window(self):
        store = self.anonymous_store()
        old_key = store.session_key
        store[auth.SESSION_KEY] = self.user.pk
        store.cycle_key()
        store.save()

        self.assertEqual(SessionStore(session_key=old_key).load(), {})
        rotation = SessionRotation.objects.get(pk=old_key)
        self.assertEqual(
            rotation.rejection_phase, SessionRotation.STAGE_WINDOW_EXPIRED,
        )
        self.assertEqual(Session.objects.filter(user=self.user).count(), 1)

    def test_logout_revokes_old_mapping_and_blocks_late_save(self):
        store = self.anonymous_store()
        old_key = store.session_key
        store[auth.SESSION_KEY] = self.user.pk
        store.cycle_key()
        store.save()
        new_key = store.session_key

        current = SessionStore(session_key=new_key)
        current.flush()

        self.assertFalse(Session.objects.filter(pk=new_key).exists())
        self.assertEqual(
            current.rotation_report()['old_session_key'], old_key,
        )
        self.assertEqual(
            current.rotation_report()['stage'], SessionRotation.STAGE_LOGOUT,
        )
        self.assertEqual(SessionStore(session_key=old_key).load(), {})

        stale = SessionStore(session_key=old_key)
        stale['late'] = True
        stale.save()

        self.assertFalse(Session.objects.filter(pk=old_key).exists())
        rotation = SessionRotation.objects.get(pk=old_key)
        self.assertEqual(rotation.outcome, SessionRotation.OUTCOME_REVOKED)
        self.assertEqual(
            rotation.rejection_phase, SessionRotation.STAGE_LOGOUT,
        )

        # A response that never touched the lazy session can still attempt a
        # save at the end of the request.  It must be a no-op, not a brand-new
        # anonymous session that masks the consumed key.
        before = Session.objects.count()
        untouched = SessionStore(session_key=old_key)
        untouched.save()
        self.assertEqual(Session.objects.count(), before)
        self.assertFalse(untouched.session_key)

    def test_mapping_chain_advances_and_logout_revokes_every_old_key(self):
        store = self.anonymous_store()
        anonymous_key = store.session_key
        store.cycle_key()
        store.save()
        authenticated_old_key = store.session_key
        store[auth.SESSION_KEY] = self.user.pk
        store.cycle_key()
        store.save()
        current_key = store.session_key

        anonymous_mapping = SessionRotation.objects.get(pk=anonymous_key)
        self.assertEqual(anonymous_mapping.new_session_key, current_key)
        self.assertEqual(anonymous_mapping.user, self.user)

        SessionStore(session_key=current_key).flush()
        anonymous_mapping.refresh_from_db()
        self.assertEqual(
            anonymous_mapping.outcome, SessionRotation.OUTCOME_REVOKED,
        )
        self.assertEqual(
            anonymous_mapping.rejection_phase, SessionRotation.STAGE_LOGOUT,
        )
        self.assertEqual(SessionStore(session_key=anonymous_key).load(), {})
        self.assertEqual(
            SessionStore(session_key=authenticated_old_key).load(), {},
        )

    def test_old_mapping_is_bound_to_the_same_auth_generation(self):
        store = self.anonymous_store()
        old_key = store.session_key
        store[auth.SESSION_KEY] = self.user.pk
        store.cycle_key()
        store.save()
        new_key = store.session_key

        # Simulate the replacement session being rebound to a newer
        # generation outside the store (for example by an administrative
        # repair).  The old compatibility link must no longer read it.
        Session.objects.filter(pk=new_key).update(
            user_version=Session.objects.get(pk=new_key).user_version + 1,
        )
        self.assertEqual(SessionStore(session_key=old_key).load(), {})
        self.assertEqual(
            SessionRotation.objects.get(pk=old_key).rejection_phase,
            SessionRotation.STAGE_MISSING_TARGET,
        )

    def test_expired_session_is_not_revived_by_save(self):
        old_key = 'EXPIRED-SESSION-KEY'
        encoder = SessionStore(
            session_key=old_key, user_agent='Python/2.7', ip='127.0.0.1',
        )
        Session.objects.create(
            session_key=old_key,
            session_data=encoder.encode({'cart': 'apple'}),
            expire_date=now() - timedelta(seconds=1),
            user_agent='Python/2.7',
            ip='127.0.0.1',
        )

        store = SessionStore(
            session_key=old_key, user_agent='Python/2.7', ip='127.0.0.1',
        )
        self.assertEqual(store.load(), {})
        store.save()
        expired = Session.objects.get(pk=old_key)
        self.assertLessEqual(expired.expire_date, now())
        self.assertNotEqual(store.session_key, old_key)
        self.assertFalse(
            Session.objects.filter(
                pk=old_key, expire_date__gt=now(),
            ).exists()
        )

    def test_failed_rotation_rolls_back_old_and_new_keys(self):
        store = self.anonymous_store()
        old_key = store.session_key
        store[auth.SESSION_KEY] = self.user.pk
        store.cycle_key()
        new_key = store.session_key

        with patch.object(
            SessionRotation, 'save',
            side_effect=DatabaseError('audit store unavailable'),
        ):
            with self.assertRaises(DatabaseError):
                store.save()

        self.assertTrue(Session.objects.filter(pk=old_key).exists())
        self.assertFalse(Session.objects.filter(pk=new_key).exists())
        self.assertFalse(SessionRotation.objects.filter(pk=old_key).exists())

    def test_rotation_can_be_retried_after_a_transient_failure(self):
        store = self.anonymous_store()
        old_key = store.session_key
        store[auth.SESSION_KEY] = self.user.pk
        store.cycle_key()
        new_key = store.session_key

        original_save = SessionRotation.save
        attempts = {'count': 0}

        def flaky_save(instance, *args, **kwargs):
            attempts['count'] += 1
            if attempts['count'] == 1:
                raise DatabaseError('temporary audit failure')
            return original_save(instance, *args, **kwargs)

        with patch.object(SessionRotation, 'save', flaky_save):
            with self.assertRaises(DatabaseError):
                store.save()
            store.save()

        self.assertFalse(Session.objects.filter(pk=old_key).exists())
        session = Session.objects.get(pk=new_key)
        self.assertEqual(session.user, self.user)
        self.assertEqual(
            SessionRotation.objects.get(pk=old_key).new_session_key,
            new_key,
        )
