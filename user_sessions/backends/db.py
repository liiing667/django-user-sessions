import copy
import logging
from datetime import timedelta

from asgiref.sync import sync_to_async
from django.conf import settings
from django.contrib import auth
from django.contrib.sessions.backends.db import SessionStore as DBStore
from django.db import DatabaseError, IntegrityError, router, transaction
from django.utils import timezone


logger = logging.getLogger(__name__)


def get_rotation_grace_seconds():
    """
    Return the compatibility window for reading a rotated session key.

    Several setting names are accepted so applications can upgrade without
    having to change an existing configuration.  The default is deliberately
    short: mapped reads are a compatibility aid, not a second valid session.
    """
    names = (
        'SESSION_ROTATION_GRACE_SECONDS',
        'SESSION_KEY_ROTATION_GRACE_SECONDS',
        'SESSION_ROTATION_GRACE',
        'SESSION_KEY_ROTATION_GRACE',
        'SESSION_ROTATION_WINDOW',
        'SESSION_KEY_ROTATION_WINDOW',
    )
    value = None
    for name in names:
        value = getattr(settings, name, None)
        if value is not None:
            break
    if value is None:
        value = 30
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 30


def _rotation_model():
    # Imported lazily: user_sessions.models imports SessionStore at module
    # load time.
    from ..models import SessionRotation

    return SessionRotation


class SessionStore(DBStore):
    """
    Implements database session store.

    Session keys are single-use.  Rotation (login, password changes, explicit
    cycle_key calls) is committed as one transaction containing:

    * a durable mapping from the consumed old key to the replacement key;
    * the replacement session row, including its user and user_version;
    * deletion of the old row.

    If any part fails, the transaction rolls back and the old session remains
    intact.  Once it commits, a late response that still carries the old key
    can only update an existing row; it can never INSERT the old key again.
    """

    def __init__(self, session_key=None, user_agent=None, ip=None):
        super().__init__(session_key)
        # Truncate user_agent string to max_length of the CharField
        self.user_agent = user_agent[:200] if user_agent else user_agent
        self.ip = ip
        self.user_id = None
        self.user_version = 0

        self._initial_session_key = session_key
        self._rotation_source_key = None
        self._rotation_pending = False
        self._mapped_from_key = None
        self._mapped_authenticated_key = None
        self._mapped_snapshot = None
        self._resign_source_key = None
        self._resign_target_key = None
        self._invalidated = False
        self._rejection_phase = None
        self._last_rotation = None
        self._user_version_dirty = False
        self._terminal = False
        self._requested_new_key = None

    # Used by superclass to get self.model, which is used elsewhere
    @classmethod
    def get_model_class(cls):
        # Avoids a circular import and allows importing SessionStore when
        # user_sessions is not in INSTALLED_APPS
        from ..models import Session

        return Session

    def _get_new_session_key(self):
        Rotation = _rotation_model()
        for _ in range(100):
            key = super()._get_new_session_key()
            if not Rotation.objects.filter(pk=key).exists():
                return key
        raise RuntimeError('unable to allocate a fresh session key')

    @property
    def rotation(self):
        """The durable rotation record associated with this store, if any."""
        key = self._mapped_from_key or self._initial_session_key
        if key is not None:
            current = self._rotation_for_display(key)
            if current is not None:
                self._last_rotation = current
        elif self._last_rotation is not None:
            current = self._rotation_for_display(self._last_rotation.pk)
            if current is not None:
                self._last_rotation = current
        return self._last_rotation

    @property
    def rejection_phase(self):
        if self._rejection_phase:
            return self._rejection_phase
        rotation = self.rotation
        return rotation.rejection_phase if rotation is not None else ''

    @property
    def invalidated(self):
        return self._invalidated

    @property
    def audit(self):
        return self.rotation

    @property
    def last_rotation(self):
        return self.rotation

    @property
    def rotation_audit(self):
        return self.rotation

    @property
    def old_session_key(self):
        key = (
            self._rotation_source_key
            or self._mapped_from_key
            or self._initial_session_key
        )
        rotation = self.rotation
        if (
            rotation is not None
            and rotation.new_session_key == key
        ):
            return rotation.old_session_key
        return key

    @property
    def new_session_key(self):
        key = self.session_key
        if key is None:
            return None
        rotation = self.rotation
        if rotation is not None and rotation.new_session_key == key:
            return key
        if key != self.old_session_key:
            return key
        return None

    @property
    def old_key(self):
        return self.old_session_key

    @property
    def new_key(self):
        return self.new_session_key

    @property
    def rotated_from(self):
        return self.old_session_key

    @property
    def rotated_to(self):
        return self.new_session_key

    def get_rotation(self, session_key=None):
        """Return the durable rotation record for a consumed key."""
        if session_key is not None:
            return self._rotation_for_display(session_key)
        key = self._mapped_from_key or self._initial_session_key
        if key is not None:
            rotation = self._rotation_for_display(key)
            if rotation is not None:
                return rotation
        if self._last_rotation is not None:
            return self._rotation_for_display(self._last_rotation.pk)
        return None

    def rotation_report(self, session_key=None):
        rotation = self.get_rotation(session_key)
        return rotation.as_dict() if rotation is not None else {}

    audit_report = rotation_report

    def __setitem__(self, key, value):
        if key == auth.SESSION_KEY:
            if self.user_id != value:
                self._user_version_dirty = True
            self.user_id = value
            if value is None:
                self.user_version = 0
        super().__setitem__(key, value)

    def __delitem__(self, key):
        if key == auth.SESSION_KEY:
            self.user_id = None
            self.user_version = 0
            self._user_version_dirty = False
        super().__delitem__(key)

    def update(self, dict_):
        if auth.SESSION_KEY in dict_:
            if self.user_id != dict_[auth.SESSION_KEY]:
                self._user_version_dirty = True
            self.user_id = dict_[auth.SESSION_KEY]
            if self.user_id is None:
                self.user_version = 0
        super().update(dict_)

    def setdefault(self, key, value):
        if key == auth.SESSION_KEY:
            if key in self._session:
                actual = self._session[key]
                if self.user_id != actual:
                    self._user_version_dirty = True
                self.user_id = actual
            elif self.user_id != value:
                self._user_version_dirty = True
                self.user_id = value
                if value is None:
                    self.user_version = 0
        return super().setdefault(key, value)

    def pop(self, key, *args):
        if key == auth.SESSION_KEY:
            self.user_id = None
            self.user_version = 0
            self._user_version_dirty = False
        return super().pop(key, *args)

    def popitem(self):
        key, value = self._session.popitem()
        self.modified = True
        if key == auth.SESSION_KEY:
            self.user_id = None
            self.user_version = 0
            self._user_version_dirty = False
        return key, value

    def _lookup_rotation(self, session_key):
        if not session_key:
            return None
        Rotation = _rotation_model()
        return Rotation.objects.filter(old_session_key=session_key).first()

    def _rotation_for_display(self, session_key):
        if not session_key:
            return None
        rotation = self._lookup_rotation(session_key)
        if rotation is not None:
            return rotation
        Rotation = _rotation_model()
        return Rotation.objects.filter(
            new_session_key=session_key,
        ).order_by('-created_at').first()

    def _mapped_session(self, rotation, at):
        """
        Follow the durable rotation chain until a live replacement is found.

        A chain is needed because a mapped read may itself be re-signed, and
        an old compatibility row must not point at an already consumed key.
        """
        Session = self.model
        Rotation = _rotation_model()
        seen = set()
        current = rotation
        while current is not None and current.new_session_key:
            key = current.new_session_key
            if key in seen:
                return None, current
            seen.add(key)
            session = Session.objects.filter(
                session_key=key, expire_date__gt=at,
            ).first()
            if session is not None:
                # The compatibility link belongs to one authenticated
                # generation.  If the replacement row has since been rebound
                # to another user or generation, the old key must not read
                # it, even if the timing window is still open.
                target_version = getattr(session, 'user_version', 0) or 0
                if session.user_id != current.user_id:
                    return None, current
                if target_version != (current.user_version or 0):
                    return None, current
                return session, current
            next_rotation = Rotation.objects.filter(
                old_session_key=key,
            ).first()
            if next_rotation is None:
                return None, current
            if next_rotation.outcome != next_rotation.OUTCOME_ACCEPTED:
                return None, next_rotation
            current = next_rotation
        return None, current

    # Used in DBStore.load()
    def _get_session_from_db(self):
        key = self.session_key
        s = super()._get_session_from_db()
        if s is None:
            if key is None:
                return None
            return self._map_or_reject_retired_key(key)

        self.user_id = s.user_id
        self.user_version = getattr(s, 'user_version', 0) or 0
        # do not overwrite user_agent/ip, as those might have been updated
        if self.user_agent != s.user_agent or self.ip != s.ip:
            self.modified = True
        return s

    def load(self):
        data = super().load()
        # DBStore.load() normally leaves caching to _get_session().  Caching
        # here is important for direct load() callers: a mapped read must be
        # able to re-sign the replacement row without reloading the
        # (already consumed) old key.
        self._session_cache = data
        if self._mapped_authenticated_key:
            self._mapped_snapshot = copy.deepcopy(data)
        return data

    def _map_or_reject_retired_key(self, old_key):
        """
        Resolve a key that no longer has a live Session row.

        A successful mapping returns the replacement row's data for one
        compatibility window and schedules a fresh key.  The old key is never
        written back, so this path cannot revive it.
        """
        rotation = self._lookup_rotation(old_key)
        if rotation is None:
            self._session_key = None
            self.user_id = None
            self.user_version = 0
            self._invalidated = True
            return None

        self._last_rotation = rotation
        at = timezone.now()
        if rotation.outcome == rotation.OUTCOME_REVOKED:
            phase = (
                rotation.rejection_phase
                or rotation.stage
                or rotation.STAGE_LOGOUT
            )
            self._reject_retired_key(
                old_key,
                phase,
                detail='retired key loaded after logout/revocation',
            )
            return None
        if rotation.outcome != rotation.OUTCOME_ACCEPTED:
            phase = rotation.rejection_phase or rotation.stage or rotation.STAGE_LOAD
            self._reject_retired_key(
                old_key, phase,
                detail='retired key loaded after a rejected rotation',
            )
            return None
        if not rotation.is_within_window(at):
            self._reject_retired_key(
                old_key, rotation.STAGE_WINDOW_EXPIRED,
                detail='retired key outside its compatibility window',
            )
            return None

        session, active_rotation = self._mapped_session(rotation, at)
        if session is None:
            target_expired = bool(
                rotation.new_session_key
                and self.model.objects.filter(
                    pk=rotation.new_session_key,
                    expire_date__lte=at,
                ).exists()
            )
            self._reject_retired_key(
                old_key,
                rotation.STAGE_EXPIRED if target_expired
                else rotation.STAGE_MISSING_TARGET,
                detail=(
                    'replacement session has expired'
                    if target_expired
                    else 'replacement session no longer exists'
                ),
            )
            return None

        # A mapped read of an authenticated replacement aliases the one
        # authoritative key.  It must not rotate the login key away: an old
        # page response may refresh its cookie to the current key, but it
        # cannot replace the key that login published.
        if session.user_id is not None:
            self._mapped_from_key = old_key
            self._mapped_authenticated_key = session.session_key
            self._resign_source_key = None
            self._resign_target_key = None
            self._session_key = session.session_key
            self.user_id = session.user_id
            self.user_version = getattr(session, 'user_version', 0) or 0
            self.modified = True
            self.accessed = True
            return session

        # Anonymous compatibility reads still re-sign the mapped data so a
        # stale anonymous tab does not keep using the same key indefinitely.
        target = self._get_new_session_key()
        self._mapped_from_key = old_key
        self._resign_source_key = session.session_key
        self._resign_target_key = target
        self._session_key = target
        self.user_id = session.user_id
        self.user_version = getattr(session, 'user_version', 0) or 0
        self.modified = True
        self.accessed = True

        if active_rotation is not rotation:
            # Keep the original old key associated with the current end of
            # the chain for audit purposes.
            self._last_rotation = rotation
        return session

    def _next_user_version(self, user_id):
        if user_id is None:
            return 0
        from django.db.models import Max

        current = self.model.objects.filter(
            user_id=user_id,
        ).aggregate(max_version=Max('user_version'))['max_version'] or 0
        Rotation = _rotation_model()
        audited = Rotation.objects.filter(
            user_id=user_id,
        ).aggregate(max_version=Max('user_version'))['max_version'] or 0
        return max(current, audited) + 1

    def _rotation_values(self, old_key, new_key, user_id, user_version,
                         outcome, phase, stage, detail='', grace_until=None,
                         rejection_phase=''):
        return {
            'old_session_key': old_key,
            'new_session_key': new_key,
            'user_id': user_id,
            'user_version': user_version,
            'outcome': outcome,
            'phase': phase,
            'stage': stage,
            'rejection_phase': rejection_phase,
            'detail': detail[:255],
            'grace_until': grace_until,
        }

    def _reject_retired_key(self, old_key, phase, detail='', new_key=None,
                            user_id=None, using=None):
        """
        Persist a rejection without changing session data.

        The audit write is best-effort with respect to availability, but the
        session state has already been rejected before this method is called.
        A late response therefore cannot resurrect a key even if audit
        storage itself is temporarily unavailable.
        """
        Rotation = _rotation_model()
        using = using or router.db_for_write(Rotation)
        now = timezone.now()
        try:
            with transaction.atomic(using=using):
                rotation = Rotation.objects.using(using).select_for_update() \
                    .filter(old_session_key=old_key).first()
                if rotation is None:
                    rotation = Rotation.objects.using(using).create(
                        **self._rotation_values(
                            old_key=old_key,
                            new_key=new_key,
                            user_id=(
                                user_id if user_id is not None
                                else self.user_id
                            ),
                            user_version=self.user_version,
                            outcome=Rotation.OUTCOME_REJECTED,
                            phase=Rotation.PHASE_REJECTED,
                            stage=phase,
                            rejection_phase=phase,
                            detail=detail,
                        )
                    )
                else:
                    if rotation.outcome == Rotation.OUTCOME_REVOKED:
                        rotation.phase = Rotation.PHASE_REVOKED
                    else:
                        rotation.outcome = Rotation.OUTCOME_REJECTED
                        rotation.phase = Rotation.PHASE_REJECTED
                    rotation.stage = phase
                    rotation.rejection_phase = phase
                    rotation.rejected_at = now
                    if new_key:
                        rotation.new_session_key = new_key
                    if user_id is not None:
                        rotation.user_id = user_id
                    rotation.detail = detail[:255]
                    rotation.save(update_fields=[
                        'outcome', 'phase', 'stage', 'rejection_phase',
                        'rejected_at', 'new_session_key', 'user', 'detail',
                        'updated_at',
                    ])
                self._last_rotation = rotation
        except (DatabaseError, IntegrityError) as exc:
            logger.warning('Unable to persist session rejection audit: %s', exc)

        self._invalidated = True
        self._rejection_phase = phase
        self._terminal = True
        self._session_key = None
        self._session_cache = {}
        self.user_id = None
        self.user_version = 0
        self._rotation_pending = False
        self._rotation_source_key = None
        self._mapped_from_key = None
        self._mapped_authenticated_key = None
        self._mapped_snapshot = None
        self._resign_source_key = None
        self._resign_target_key = None

    def create(self):
        # Keep the values that triggered session creation in memory.  Django's
        # DBStore.create() leaves the cache untouched; clearing it here would
        # lose anonymous data when a login/rotation happens later in the same
        # request.
        data = self._get_session(no_load=False)
        if self.user_id is not None and self.user_version == 0:
            self.user_version = self._next_user_version(self.user_id)
        super().create()
        self._session_cache = data
        if self._initial_session_key is None:
            self._initial_session_key = self.session_key
        self._invalidated = False
        self._rejection_phase = None
        self._rotation_pending = False
        self._rotation_source_key = None
        self._mapped_from_key = None
        self._mapped_authenticated_key = None
        self._mapped_snapshot = None
        self._resign_source_key = None
        self._resign_target_key = None
        self._terminal = False
        self._user_version_dirty = False

    def save(self, must_create=False):
        if self._rotation_pending:
            return self._commit_pending_rotation(must_create=must_create)
        if self._resign_source_key:
            return self._commit_resign(must_create=must_create)
        if (
            self._mapped_authenticated_key
            and self.session_key == self._mapped_authenticated_key
        ):
            return self._save_authenticated_mapping()
        if self._terminal and self.session_key is None:
            # This store arrived with a key that has been consumed.  A late
            # response must not silently create a new anonymous session.
            return
        if self.session_key is None:
            return self.create()
        if must_create:
            return super().save(must_create=True)
        return self._save_existing()

    def _save_authenticated_mapping(self):
        """
        Save an old-key request that was mapped to the live auth session.

        Reads are allowed during the compatibility window.  Writes made by a
        stale page are discarded and recorded, while the login-published key
        and the authenticated row stay untouched.
        """
        Rotation = _rotation_model()
        now = timezone.now()
        rotation = self._lookup_rotation(self._mapped_from_key)
        target_key = (
            rotation.new_session_key
            if rotation is not None
            and rotation.outcome == Rotation.OUTCOME_ACCEPTED
            and rotation.new_session_key
            else self._mapped_authenticated_key
        )
        target = self.model.objects.filter(
            pk=target_key,
            expire_date__gt=now,
        ).first()
        target_version = getattr(target, 'user_version', 0) or 0
        if rotation is None or rotation.outcome != Rotation.OUTCOME_ACCEPTED:
            phase = (
                (
                    rotation.rejection_phase
                    or rotation.stage
                    or Rotation.STAGE_LOGOUT
                )
                if rotation is not None
                and rotation.outcome == Rotation.OUTCOME_REVOKED
                else (
                    rotation.rejection_phase
                    if rotation is not None and rotation.rejection_phase
                    else Rotation.STAGE_LATE_SAVE
                )
            )
            self._reject_retired_key(
                self._mapped_from_key,
                phase,
                detail='mapped key no longer has an accepted generation',
            )
            return
        if not rotation.is_within_window(now):
            self._reject_retired_key(
                self._mapped_from_key,
                Rotation.STAGE_WINDOW_EXPIRED,
                detail='mapped authenticated session is outside its window',
            )
            return
        if (
            target is None
            or target.user_id != rotation.user_id
            or target_version != (rotation.user_version or 0)
        ):
            expired_target = bool(
                target is None
                and self.model.objects.filter(
                    pk=target_key,
                    expire_date__lte=now,
                ).exists()
            )
            self._reject_retired_key(
                self._mapped_from_key,
                Rotation.STAGE_EXPIRED if expired_target
                else Rotation.STAGE_MISSING_TARGET,
                detail=(
                    'mapped authenticated session has expired'
                    if expired_target
                    else 'mapped authenticated session is no longer live'
                ),
            )
            return
        self._session_key = target.session_key
        self._mapped_authenticated_key = target.session_key
        data = self._get_session()
        snapshot = self._mapped_snapshot
        if snapshot is not None and data != snapshot:
            self._mark_mapping_rejected(
                self._mapped_from_key,
                'late_save',
                detail='stale mapped write discarded; login key retained',
            )
            self._session_cache = copy.deepcopy(snapshot)
            self.user_id = rotation.user_id
            self.user_version = rotation.user_version or 0
            self.modified = True
            return
        using = router.db_for_write(self.model)
        refreshed = self.model.objects.using(using).filter(
            pk=target.pk,
            user_id=rotation.user_id,
            user_version=rotation.user_version or 0,
            expire_date__gt=now,
        ).update(
            expire_date=self.get_expiry_date(),
            last_activity=now,
        )
        if not refreshed:
            self._reject_retired_key(
                self._mapped_from_key,
                Rotation.STAGE_MISSING_TARGET,
                detail='mapped authenticated session changed before refresh',
            )

    def _mark_mapping_rejected(self, old_key, phase, detail=''):
        """Record a rejection without invalidating the live replacement key."""
        Rotation = _rotation_model()
        using = router.db_for_write(Rotation)
        now = timezone.now()
        try:
            with transaction.atomic(using=using):
                rotation = Rotation.objects.using(using) \
                    .select_for_update().filter(old_session_key=old_key).first()
                if rotation is not None:
                    rotation.outcome = Rotation.OUTCOME_REJECTED
                    rotation.phase = Rotation.PHASE_REJECTED
                    rotation.stage = phase
                    rotation.rejection_phase = phase
                    rotation.rejected_at = now
                    rotation.detail = detail[:255]
                    rotation.save(update_fields=[
                        'outcome', 'phase', 'stage', 'rejection_phase',
                        'rejected_at', 'detail', 'updated_at',
                    ])
                    self._last_rotation = rotation
        except (DatabaseError, IntegrityError) as exc:
            logger.warning('Unable to persist mapped rejection audit: %s', exc)
        self._rejection_phase = phase

    def _save_existing(self):
        data = self._get_session()
        if self._resign_source_key:
            # Loading the old key selected a live replacement and scheduled
            # a secure re-sign.  Commit that path instead of trying to update
            # the not-yet-persisted target key directly.
            return self._commit_resign()
        if (
            self._mapped_authenticated_key
            and self.session_key == self._mapped_authenticated_key
        ):
            return self._save_authenticated_mapping()
        if self.session_key is None:
            if self._terminal:
                return
            # The row disappeared or expired while it was being loaded.  Use
            # a fresh key instead of updating (and thereby reviving) the old
            # one.
            self._session_cache = data
            return self.create()

        if self.user_id is not None and (
            self.user_version == 0 or self._user_version_dirty
        ):
            self.user_version = self._next_user_version(self.user_id)
            self._user_version_dirty = False

        obj = self.create_model_instance(data)
        using = router.db_for_write(self.model, instance=obj)
        now = timezone.now()

        values = {}
        for field in obj._meta.concrete_fields:
            if field.primary_key:
                continue
            value = getattr(obj, field.attname)
            if getattr(field, 'auto_now', False):
                value = now
            values[field.attname] = value

        # A session key that has been deleted or rotated must stay invalid.
        # A stale request may already have loaded the old row, and Django's
        # Model.save() would otherwise re-insert it when it is no longer in
        # the database.  Only update an existing, still-live row here; new
        # sessions are inserted exclusively through create().
        with transaction.atomic(using=using):
            saved = self.model.objects.using(using).filter(
                pk=obj.pk,
                expire_date__gt=now,
            ).update(**values)
            if saved and self.user_id is not None:
                # Anonymous rotation may have been committed before the
                # authentication keys were written (for example an explicit
                # cycle_key/save followed by login in the same request).
                # Attach that identity to the durable old -> new mapping.
                Rotation = _rotation_model()
                Rotation.objects.using(using).filter(
                    new_session_key=self.session_key,
                    outcome=Rotation.OUTCOME_ACCEPTED,
                ).update(
                    user_id=self.user_id,
                    user_version=self.user_version,
                    updated_at=now,
                )
            if not saved:
                rotation = self._lookup_rotation(self.session_key)
                if (
                    rotation is not None
                    and rotation.outcome == rotation.OUTCOME_ACCEPTED
                    and rotation.new_session_key
                    and rotation.is_within_window(now)
                ):
                    target = self.model.objects.using(using).filter(
                        pk=rotation.new_session_key,
                        expire_date__gt=now,
                    ).first()
                    target_version = (
                        getattr(target, 'user_version', 0) or 0
                        if target is not None else 0
                    )
                    if (
                        target is not None
                        and target.user_id is not None
                        and target.user_id == rotation.user_id
                        and target_version == (rotation.user_version or 0)
                    ):
                        # The request loaded the anonymous key before login.
                        # Its stale writes are discarded, but the response
                        # can safely adopt the authenticated key login
                        # published instead of deleting the browser cookie.
                        self._mark_mapping_rejected(
                            rotation.old_session_key,
                            'late_save',
                            detail=(
                                'stale pre-login response discarded; '
                                'authenticated login key retained'
                            ),
                        )
                        self._session_key = target.session_key
                        self._mapped_from_key = rotation.old_session_key
                        self._mapped_authenticated_key = target.session_key
                        self._session_cache = self.decode(target.session_data)
                        self._mapped_snapshot = copy.deepcopy(
                            self._session_cache,
                        )
                        self.user_id = target.user_id
                        self.user_version = target_version
                        self._invalidated = False
                        self._terminal = False
                        self.modified = True
                        return
                if self.model.objects.using(using).filter(pk=obj.pk).exists():
                    phase = 'expired'
                elif rotation is not None:
                    if rotation.outcome == rotation.OUTCOME_REVOKED:
                        phase = (
                            rotation.rejection_phase
                            or rotation.stage
                            or rotation.STAGE_LOGOUT
                        )
                    elif rotation.outcome == rotation.OUTCOME_REJECTED:
                        phase = (
                            rotation.rejection_phase
                            or rotation.stage
                            or rotation.STAGE_LATE_SAVE
                        )
                    elif not rotation.is_within_window(now):
                        phase = rotation.STAGE_WINDOW_EXPIRED
                    elif rotation.new_session_key and self.model.objects \
                            .using(using).filter(
                                pk=rotation.new_session_key,
                                expire_date__lte=now,
                            ).exists():
                        phase = rotation.STAGE_EXPIRED
                    else:
                        phase = rotation.STAGE_LATE_SAVE
                else:
                    phase = 'deleted'
                self._reject_retired_key(
                    self.session_key,
                    phase,
                    detail='stale session save refused; key is no longer live',
                    using=using,
                )

    def _commit_pending_rotation(self, must_create=False):
        old_key = self._rotation_source_key
        new_key = self.session_key
        if old_key is not None and old_key == new_key:
            new_key = self._get_new_session_key()
            self._session_key = new_key
        if old_key is None or new_key is None:
            # Nothing meaningful to rotate.  Fall back to a normal save so
            # callers that only changed data still get standard semantics.
            self._rotation_pending = False
            self._rotation_source_key = None
            if self.session_key is None:
                return self.create()
            if must_create:
                return super().save(must_create=True)
            return self._save_existing()

        data = self._get_session()
        user_id = self.user_id
        if user_id is not None:
            self.user_version = self._next_user_version(user_id)
        else:
            self.user_version = self.user_version or 0

        obj = self.create_model_instance(data)
        using = router.db_for_write(self.model, instance=obj)
        Rotation = _rotation_model()
        now = timezone.now()
        grace_until = now + timedelta(seconds=get_rotation_grace_seconds())

        try:
            with transaction.atomic(using=using):
                old_session = self.model.objects.using(using) \
                    .select_for_update().filter(pk=old_key).first()
                existing = Rotation.objects.using(using) \
                    .select_for_update().filter(old_session_key=old_key).first()
                if existing is not None:
                    # Another request consumed this key first.  Never create
                    # a second candidate; only one new key may become live.
                    # Keep the winner's accepted mapping intact so legitimate
                    # concurrent tabs still read the same authenticated
                    # generation, and record the losing candidate separately
                    # in the audit stage/details.
                    existing.stage = Rotation.STAGE_CONCURRENT
                    existing.rejection_phase = Rotation.STAGE_CONCURRENT
                    existing.rejected_at = now
                    existing.detail = (
                        f'concurrent rotation rejected candidate {new_key}'
                    )[:255]
                    existing.save(update_fields=[
                        'stage', 'rejection_phase', 'rejected_at', 'detail',
                        'updated_at',
                    ])
                    self._invalidated = True
                    self._rejection_phase = Rotation.STAGE_CONCURRENT
                    self._terminal = True
                    self._session_key = None
                    self._session_cache = {}
                    self.user_id = None
                    self.user_version = 0
                    self._rotation_pending = False
                    self._rotation_source_key = None
                    self._mapped_authenticated_key = None
                    self._mapped_snapshot = None
                    return

                # The mapping is written before the candidate row.  Its
                # primary key enforces single consumption even if two
                # workers race on a database where SELECT FOR UPDATE is a
                # no-op.
                rotation = Rotation.objects.using(using).create(
                    **self._rotation_values(
                        old_key=old_key,
                        new_key=new_key,
                        user_id=user_id,
                        user_version=self.user_version,
                        outcome=Rotation.OUTCOME_ACCEPTED,
                        phase=Rotation.PHASE_ROTATION,
                        stage=Rotation.STAGE_COMMIT,
                        detail='session key rotated',
                        grace_until=grace_until,
                    )
                )
                obj.save(force_insert=True, using=using)
                if not self.model.objects.using(using).filter(
                    pk=new_key,
                ).exists():
                    raise IntegrityError(
                        'replacement session key was not published'
                    )
                # Collapse earlier compatibility links onto the current
                # replacement.  This keeps a logout/revocation of the newest
                # key authoritative for every retired key in the chain while
                # retaining the original audit rows.
                prior = Rotation.objects.using(using).filter(
                    new_session_key=old_key,
                    outcome=Rotation.OUTCOME_ACCEPTED,
                )
                prior_values = {
                    'new_session_key': new_key,
                    'outcome': Rotation.OUTCOME_ACCEPTED,
                    'phase': Rotation.PHASE_ROTATION,
                    'stage': Rotation.STAGE_COMMIT,
                    'rejection_phase': '',
                    'updated_at': now,
                }
                if user_id is not None:
                    prior_values['user_id'] = user_id
                    prior_values['user_version'] = self.user_version
                prior.update(**prior_values)
                if old_session is not None:
                    old_session._rotation_consumed = True
                    old_session.delete(using=using)
                self._last_rotation = rotation
        except IntegrityError:
            # The old key or the candidate key was consumed by a concurrent
            # writer after our lookup.  The atomic block rolled everything
            # back; record the rejection without creating a replacement.
            self._reject_retired_key(
                old_key,
                Rotation.STAGE_CONCURRENT,
                detail='concurrent rotation lost the single-consumer race',
                new_key=new_key,
                user_id=user_id,
                using=using,
            )
            return
        except DatabaseError:
            try:
                consumed = (
                    not self.model.objects.filter(pk=old_key).exists()
                    or Rotation.objects.filter(
                        old_session_key=old_key,
                    ).exists()
                )
            except DatabaseError:
                raise
            if not consumed:
                raise
            self._reject_retired_key(
                old_key,
                Rotation.STAGE_CONCURRENT,
                detail='rotation was consumed by a concurrent writer',
                new_key=new_key,
                user_id=user_id,
                using=using,
            )
            return

        self._rotation_pending = False
        self._rotation_source_key = None
        self._mapped_from_key = None
        self._mapped_authenticated_key = None
        self._mapped_snapshot = None
        self._invalidated = False
        self._rejection_phase = None
        self._terminal = False
        self._user_version_dirty = False

    def _commit_resign(self, must_create=False):
        source_key = self._resign_source_key
        target_key = self._resign_target_key or self.session_key
        old_key = self._mapped_from_key
        if source_key is None or target_key is None:
            self._resign_source_key = None
            self._resign_target_key = None
            return self._save_existing()

        data = self._get_session()
        obj = self.create_model_instance(data)
        using = router.db_for_write(self.model, instance=obj)
        Rotation = _rotation_model()
        now = timezone.now()

        try:
            with transaction.atomic(using=using):
                source = self.model.objects.using(using) \
                    .select_for_update().filter(pk=source_key).first()
                if source is None:
                    self._reject_retired_key(
                        old_key or source_key,
                        Rotation.STAGE_MISSING_TARGET,
                        detail='mapped session disappeared before re-sign',
                        using=using,
                    )
                    return

                rotation = None
                if old_key:
                    rotation = Rotation.objects.using(using) \
                        .select_for_update().filter(old_session_key=old_key).first()
                if rotation is not None:
                    rotation.new_session_key = target_key
                    rotation.phase = Rotation.PHASE_RESIGNED
                    rotation.stage = Rotation.STAGE_COMMIT
                    rotation.rejection_phase = ''
                    rotation.detail = 'old key mapping re-signed to a fresh key'
                    rotation.save(update_fields=[
                        'new_session_key', 'phase', 'stage', 'rejection_phase',
                        'detail', 'updated_at',
                    ])

                Rotation.objects.using(using).create(
                    **self._rotation_values(
                        old_key=source_key,
                        new_key=target_key,
                        user_id=self.user_id,
                        user_version=self.user_version,
                        outcome=Rotation.OUTCOME_ACCEPTED,
                        phase=Rotation.PHASE_RESIGNED,
                        stage=Rotation.STAGE_COMMIT,
                        detail='mapped session re-signed to a fresh key',
                        grace_until=now + timedelta(
                            seconds=get_rotation_grace_seconds()
                        ),
                    )
                )
                obj.save(force_insert=True, using=using)
                if not self.model.objects.using(using).filter(
                    pk=target_key,
                ).exists():
                    raise IntegrityError(
                        'mapped replacement key was not published'
                    )
                source._rotation_consumed = True
                source.delete(using=using)
                self._last_rotation = rotation
        except IntegrityError:
            self._reject_retired_key(
                old_key or source_key,
                Rotation.STAGE_CONCURRENT,
                detail='mapped re-sign lost its single-consumer race',
                new_key=target_key,
                using=using,
            )
            return
        except DatabaseError:
            try:
                consumed = not self.model.objects.filter(pk=source_key).exists()
            except DatabaseError:
                raise
            if not consumed:
                raise
            self._reject_retired_key(
                old_key or source_key,
                Rotation.STAGE_CONCURRENT,
                detail='mapped session was consumed concurrently',
                new_key=target_key,
                using=using,
            )
            return

        self._resign_source_key = None
        self._resign_target_key = None
        self._mapped_from_key = None
        self._mapped_authenticated_key = None
        self._mapped_snapshot = None
        self._invalidated = False
        self._rejection_phase = None
        self._terminal = False
        self._user_version_dirty = False

    def cycle_key(self):
        """
        Prepare a rotation without committing it yet.

        Django's login() calls cycle_key() and only afterwards writes the
        authenticated user keys.  Deferring the commit to save() lets the old
        key, the user and the replacement key be written in one transaction.
        """
        if self._resign_source_key:
            source_key = self._resign_source_key
            self._resign_source_key = None
            self._resign_target_key = None
        elif self._rotation_pending:
            source_key = self._rotation_source_key
        else:
            source_key = self.session_key

        data = self._session
        if source_key is None:
            self.create()
            self._session_cache = data
            self.modified = True
            self.accessed = True
            return

        target_key = self._requested_new_key
        self._requested_new_key = None
        if target_key is None:
            for _ in range(100):
                target_key = self._get_new_session_key()
                if target_key != source_key:
                    break
            else:
                raise RuntimeError('unable to allocate a fresh session key')
        self._rotation_source_key = source_key
        self._rotation_pending = True
        self._mapped_authenticated_key = None
        self._mapped_snapshot = None
        self._session_key = target_key
        self._session_cache = data
        self.modified = True
        self.accessed = True
        self._invalidated = False
        self._rejection_phase = None

    def migrate_anonymous(self, user=None, new_session_key=None):
        """
        Explicitly promote the current anonymous data to a rotated session.

        This is the operation login() reaches indirectly through
        cycle_key().  It is public so applications can perform an explicit
        migration (for example during an account-upgrade flow) without
        relying on generic response ordering.
        """
        if new_session_key is not None:
            self._requested_new_key = new_session_key
        if user is not None:
            self.user_id = getattr(user, 'pk', user)
            self._user_version_dirty = True
        self.cycle_key()
        self.save()
        return self.session_key

    migrate_to_user = migrate_anonymous
    promote_to_user = migrate_anonymous
    migrate_anonymous_data = migrate_anonymous
    migrate_anonymous_session = migrate_anonymous
    migrate_session_data = migrate_anonymous

    # Used in DBStore.save()
    def create_model_instance(self, data):
        """
        Return a new instance of the session model object, which represents the
        current session state. Intended to be used for saving the session data
        to the database.
        """
        if self.user_id is not None and self.user_version == 0:
            self.user_version = self._next_user_version(self.user_id)
        return self.model(
            session_key=self._get_or_create_session_key(),
            session_data=self.encode(data),
            expire_date=self.get_expiry_date(),
            user_agent=self.user_agent,
            user_id=self.user_id,
            user_version=self.user_version,
            ip=self.ip,
        )

    def delete(self, session_key=None):
        if session_key is None:
            session_key = (
                self._rotation_source_key
                or self._resign_source_key
                or self.session_key
            )
            if session_key is None:
                return
        # django.test.Client.logout() passes the cookie Morsel itself.
        session_key = getattr(session_key, 'value', session_key)

        using = router.db_for_write(self.model)
        Rotation = _rotation_model()
        now = timezone.now()
        with transaction.atomic(using=using):
            expire_date = self.model.objects.using(using).filter(
                pk=session_key,
            ).values_list('expire_date', flat=True).first()
            deleted_phase = (
                Rotation.STAGE_EXPIRED
                if expire_date is not None and expire_date <= now
                else Rotation.STAGE_LOGOUT
            )
            self.model.objects.using(using).filter(
                pk=session_key,
            ).delete()
            # A deletion is terminal for every old key that mapped to
            # this session.  Restarting the process must not make the
            # mapping readable again.
            Rotation.objects.using(using).filter(
                new_session_key=session_key,
            ).update(
                outcome=Rotation.OUTCOME_REVOKED,
                phase=Rotation.PHASE_REVOKED,
                stage=deleted_phase,
                rejection_phase=deleted_phase,
                rejected_at=now,
                detail='replacement session deleted/logged out',
                updated_at=now,
            )
            Rotation.objects.using(using).filter(
                old_session_key=session_key,
            ).update(
                outcome=Rotation.OUTCOME_REVOKED,
                phase=Rotation.PHASE_REVOKED,
                stage=deleted_phase,
                rejection_phase=deleted_phase,
                rejected_at=now,
                detail='consumed session key deleted',
                updated_at=now,
            )

        related = Rotation.objects.filter(
            new_session_key=session_key,
        ).first()
        if related is None:
            related = Rotation.objects.filter(
                old_session_key=session_key,
            ).first()
        # A logout is terminal for this store.  A subsequent login in the
        # same request must create a brand-new session instead of reviving
        # the key that was just removed.
        self._session_key = None
        self._rotation_pending = False
        self._rotation_source_key = None
        self._mapped_from_key = None
        self._mapped_authenticated_key = None
        self._mapped_snapshot = None
        self._resign_source_key = None
        self._resign_target_key = None
        self._invalidated = True
        self._terminal = True
        self._rejection_phase = deleted_phase
        if related is not None:
            self._last_rotation = related

    def clear(self):
        mapped_key = self._mapped_authenticated_key
        mapped_snapshot = self._mapped_snapshot
        super().clear()
        self.user_id = None
        self.user_version = 0
        self._user_version_dirty = False
        self._terminal = False
        if mapped_key and self.session_key == mapped_key:
            # A mapped old-key response cannot clear the live login session.
            # Keep the read-only guard so the write is discarded on save.
            self._mapped_authenticated_key = mapped_key
            self._mapped_snapshot = mapped_snapshot
        else:
            self._mapped_authenticated_key = None
            self._mapped_snapshot = None

    def flush(self):
        old_key = (
            self._rotation_source_key
            or self._resign_source_key
            or self.session_key
            or self._initial_session_key
        )
        target_key = None
        if old_key:
            rotation = self._lookup_rotation(old_key)
            if rotation is not None and rotation.new_session_key:
                target = self.model.objects.filter(
                    pk=rotation.new_session_key,
                ).values('user_id', 'user_version').first()
                if (
                    target is not None
                    and target['user_id'] == rotation.user_id
                    and (target['user_version'] or 0)
                    == (rotation.user_version or 0)
                ):
                    target_key = rotation.new_session_key
        self.clear()
        using = router.db_for_write(self.model)
        with transaction.atomic(using=using):
            if old_key:
                self.delete(old_key)
            else:
                self.delete()
            if target_key and target_key != old_key:
                self.delete(target_key)
        self._session_key = None
        self._initial_session_key = None
        self._rotation_pending = False
        self._mapped_from_key = None
        self._mapped_authenticated_key = None
        self._mapped_snapshot = None
        self._resign_source_key = None
        self._resign_target_key = None
        self._terminal = True

    # Django's database backend exposes async variants separately.  Route
    # them through the same single-consumer logic as the synchronous path.
    async def aload(self):
        return await sync_to_async(self.load)()

    async def asave(self, must_create=False):
        return await sync_to_async(self.save)(must_create)

    async def acreate(self):
        return await sync_to_async(self.create)()

    async def adelete(self, session_key=None):
        return await sync_to_async(self.delete)(session_key)

    async def acycle_key(self):
        return await sync_to_async(self.cycle_key)()

    async def aflush(self):
        return await sync_to_async(self.flush)()
