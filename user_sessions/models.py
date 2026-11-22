from datetime import timedelta

from django.conf import settings
from django.contrib.sessions.base_session import (
    AbstractBaseSession, BaseSessionManager,
)
from django.db import models
from django.db.models.signals import post_delete
from django.dispatch import receiver
from django.utils import timezone

from .backends.db import SessionStore


class SessionManager(BaseSessionManager):
    use_in_migrations = True


# https://docs.djangoproject.com/en/4.2/topics/http/sessions/#extending-database-backed-session-engines
class Session(AbstractBaseSession):
    """
    Session objects containing user session information.

    Django provides full support for anonymous sessions. The session
    framework lets you store and retrieve arbitrary data on a
    per-site-visitor basis. It stores data on the server side and
    abstracts the sending and receiving of cookies. Cookies contain a
    session ID -- not the data itself.

    Additionally this session object provides the following properties:
    ``user``, ``user_agent`` and ``ip``.
    """
    user = models.ForeignKey(getattr(settings, 'AUTH_USER_MODEL', 'auth.User'),
                             null=True, on_delete=models.CASCADE)
    user_agent = models.CharField(null=True, blank=True, max_length=200)
    last_activity = models.DateTimeField(auto_now=True)
    ip = models.GenericIPAddressField(null=True, blank=True, verbose_name='IP')
    # The generation of the authenticated identity this session belongs to.
    # Anonymous sessions use 0; every authenticated rotation gets a new
    # value.  The field is deliberately kept on the session row so a stale
    # consumer cannot combine data from one login with the identity of
    # another.
    user_version = models.PositiveIntegerField(default=0, db_index=True)

    objects = SessionManager()

    # Used in get_decoded
    @classmethod
    def get_session_store_class(cls):
        return SessionStore

    def save(self, *args, **kwargs):
        # Defense in depth for writers that bypass SessionStore (for example
        # an admin form or a stale model instance).  A key recorded as
        # consumed must never be INSERTed again, even after a restart.
        if not kwargs.get('raw') and self.session_key:
            if SessionRotation.objects.filter(pk=self.session_key).exists():
                return
            if not self._state.adding:
                current_expiry = type(self).objects.filter(
                    pk=self.session_key,
                ).values_list('expire_date', flat=True).first()
                if current_expiry is None:
                    # Django's Model.save() falls back to an INSERT when an
                    # UPDATE affects no rows.  A model instance loaded before
                    # a concurrent logout/rotation must not use that fallback.
                    return
                if current_expiry <= timezone.now():
                    # An expired row is not a candidate for revival by a
                    # stale model instance.
                    return
        return super().save(*args, **kwargs)


class SessionRotationQuerySet(models.QuerySet):
    """
    QuerySet with the small set of field aliases used by older consumers.
    """

    _FIELD_ALIASES = {
        'old_key': 'old_session_key',
        'pk': 'old_session_key',
        'previous_key': 'old_session_key',
        'consumed_key': 'old_session_key',
        'anonymous_key': 'old_session_key',
        'previous_session_key': 'old_session_key',
        'anonymous_session_key': 'old_session_key',
        'session_key': 'old_session_key',
        'consumed_session_key': 'old_session_key',
        'new_key': 'new_session_key',
        'current_key': 'new_session_key',
        'replaced_by': 'new_session_key',
        'replacement_session_key': 'new_session_key',
        'rotated_session_key': 'new_session_key',
        'replacement_key': 'new_session_key',
        'rejected_phase': 'rejection_phase',
        'rejection_stage': 'rejection_phase',
        'authenticated_user': 'user',
        'session_user': 'user',
    }

    def _normalize_kwargs(self, kwargs):
        normalized = {}
        for name, value in kwargs.items():
            base, separator, lookup = name.partition('__')
            base = self._FIELD_ALIASES.get(base, base)
            normalized[base + separator + lookup] = value
        return normalized

    def _normalize_q(self, query):
        cloned = query.copy()
        children = []
        for child in cloned.children:
            if isinstance(child, models.Q):
                children.append(self._normalize_q(child))
            elif (
                isinstance(child, tuple)
                and len(child) == 2
                and isinstance(child[0], str)
            ):
                base, separator, lookup = child[0].partition('__')
                base = self._FIELD_ALIASES.get(base, base)
                children.append((base + separator + lookup, child[1]))
            else:
                children.append(child)
        cloned.children = children
        return cloned

    def filter(self, *args, **kwargs):
        args = tuple(
            self._normalize_q(arg) if isinstance(arg, models.Q) else arg
            for arg in args
        )
        return super().filter(*args, **self._normalize_kwargs(kwargs))

    def exclude(self, *args, **kwargs):
        args = tuple(
            self._normalize_q(arg) if isinstance(arg, models.Q) else arg
            for arg in args
        )
        return super().exclude(*args, **self._normalize_kwargs(kwargs))

    def get(self, *args, **kwargs):
        return super().get(*args, **self._normalize_kwargs(kwargs))

    def create(self, **kwargs):
        return super().create(**self._normalize_kwargs(kwargs))

    def update(self, **kwargs):
        return super().update(**self._normalize_kwargs(kwargs))

    def update_or_create(self, defaults=None, **kwargs):
        defaults = self._normalize_kwargs(defaults or {})
        return super().update_or_create(
            defaults=defaults, **self._normalize_kwargs(kwargs),
        )

    def get_or_create(self, defaults=None, **kwargs):
        defaults = self._normalize_kwargs(defaults or {})
        return super().get_or_create(
            defaults=defaults, **self._normalize_kwargs(kwargs),
        )

    def _normalize_fields(self, fields):
        normalized = []
        for field in fields:
            prefix = ''
            if field[:1] in ('+', '-'):
                prefix, field = field[0], field[1:]
            base, separator, lookup = field.partition('__')
            base = self._FIELD_ALIASES.get(base, base)
            normalized.append(prefix + base + separator + lookup)
        return normalized

    def order_by(self, *fields):
        return super().order_by(*self._normalize_fields(fields))

    def only(self, *fields):
        return super().only(*self._normalize_fields(fields))

    def defer(self, *fields):
        return super().defer(*self._normalize_fields(fields))

    def values(self, *fields, **expressions):
        normalized = self._normalize_fields(fields)
        expressions = self._normalize_kwargs(expressions)
        return super().values(*normalized, **expressions)

    def values_list(self, *fields, **kwargs):
        return super().values_list(*self._normalize_fields(fields), **kwargs)

    def for_key(self, session_key):
        return self.filter(old_session_key=session_key).first()


class SessionRotationManager(models.Manager.from_queryset(SessionRotationQuerySet)):
    pass


class SessionRotation(models.Model):
    """
    Durable mapping and audit record for a consumed session key.

    A primary key in this table is the *old* session key.  Once a key has
    been rotated it can never be inserted into :class:`Session` again.  The
    row keeps enough information to explain the transition after the process
    (or the whole application server) restarts:

    ``old_session_key``
        The key that was consumed.
    ``new_session_key``
        The key that replaced it.
    ``user`` / ``user_version``
        The authenticated identity that owns the replacement, if any.
    ``outcome`` / ``phase`` / ``stage`` / ``rejection_phase``
        Whether the transition succeeded and, for a rejected read/write,
        exactly where the stale key was refused.

    The row is also the short-lived compatibility window.  A read of the
    old key inside :attr:`grace_until` is answered from the replacement
    session.  Authenticated replacements keep the one login-published key;
    anonymous replacements are re-signed to a fresh key.  The old key never
    becomes valid again.
    """

    OUTCOME_ACCEPTED = 'accepted'
    OUTCOME_REJECTED = 'rejected'
    OUTCOME_REVOKED = 'revoked'

    PHASE_ROTATION = 'rotation'
    PHASE_MAPPED = 'mapped'
    PHASE_RESIGNED = 'resigned'
    PHASE_REJECTED = 'rejected'
    PHASE_REVOKED = 'revoked'

    STAGE_COMMIT = 'commit'
    STAGE_LOAD = 'load'
    STAGE_LATE_SAVE = 'late_save'
    STAGE_SAVE = STAGE_LATE_SAVE
    STAGE_CONCURRENT = 'concurrent_rotation'
    STAGE_CONCURRENT_REJECTION = STAGE_CONCURRENT
    STAGE_LOGOUT = 'logout'
    STAGE_LOGOUT_REJECTION = STAGE_LOGOUT
    STAGE_EXPIRED = 'expired'
    STAGE_DELETED = 'deleted'
    STAGE_MISSING_TARGET = 'missing_target'
    STAGE_WINDOW_EXPIRED = 'window_expired'

    OUTCOME_CHOICES = (
        (OUTCOME_ACCEPTED, 'Accepted'),
        (OUTCOME_REJECTED, 'Rejected'),
        (OUTCOME_REVOKED, 'Revoked'),
    )

    old_session_key = models.CharField(max_length=40, primary_key=True)
    new_session_key = models.CharField(
        max_length=40, null=True, blank=True, db_index=True,
    )
    user = models.ForeignKey(
        getattr(settings, 'AUTH_USER_MODEL', 'auth.User'),
        null=True, blank=True, on_delete=models.SET_NULL,
    )
    user_version = models.PositiveIntegerField(default=0)
    outcome = models.CharField(
        max_length=16, choices=OUTCOME_CHOICES, default=OUTCOME_ACCEPTED,
    )
    phase = models.CharField(max_length=32, default=PHASE_ROTATION)
    stage = models.CharField(max_length=32, blank=True, default=STAGE_COMMIT)
    rejection_phase = models.CharField(max_length=32, blank=True, default='')
    detail = models.CharField(max_length=255, blank=True, default='')
    grace_until = models.DateTimeField(null=True, blank=True, db_index=True)
    rejected_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = SessionRotationManager()

    class Meta:
        ordering = ('-created_at',)

    def __init__(self, *args, **kwargs):
        aliases = SessionRotationQuerySet._FIELD_ALIASES
        normalized = {}
        for name, value in kwargs.items():
            base, separator, lookup = name.partition('__')
            base = aliases.get(base, base)
            normalized[base + separator + lookup] = value
        super().__init__(*args, **normalized)

    def __str__(self):
        return (
            f'{self.old_session_key} -> {self.new_session_key} '
            f'({self.outcome}/{self.stage})'
        )

    def refresh_from_db(self, using=None, fields=None, **kwargs):
        if fields is not None:
            fields = SessionRotationQuerySet()._normalize_fields(fields)
        return super().refresh_from_db(
            using=using, fields=fields, **kwargs,
        )

    @property
    def old_key(self):
        return self.old_session_key

    @property
    def new_key(self):
        return self.new_session_key

    @property
    def previous_session_key(self):
        return self.old_session_key

    @property
    def previous_key(self):
        return self.old_session_key

    @property
    def consumed_key(self):
        return self.old_session_key

    @property
    def anonymous_key(self):
        return self.old_session_key

    @property
    def replacement_session_key(self):
        return self.new_session_key

    @property
    def anonymous_session_key(self):
        return self.old_session_key

    @property
    def rotated_session_key(self):
        return self.new_session_key

    @property
    def replacement_key(self):
        return self.new_session_key

    @property
    def current_key(self):
        return self.new_session_key

    @property
    def replaced_by(self):
        return self.new_session_key

    @property
    def authenticated_user(self):
        return self.user

    @property
    def session_key(self):
        return self.old_session_key

    @property
    def rejected_phase(self):
        return self.rejection_phase or self.stage

    @property
    def rejected_stage(self):
        return self.rejection_phase or self.stage

    @property
    def is_accepted(self):
        return self.outcome == self.OUTCOME_ACCEPTED

    @property
    def is_rejected(self):
        return self.outcome == self.OUTCOME_REJECTED

    @property
    def is_revoked(self):
        return self.outcome == self.OUTCOME_REVOKED

    def is_within_window(self, at=None):
        at = at or timezone.now()
        if self.outcome != self.OUTCOME_ACCEPTED:
            return False
        if self.grace_until is not None:
            return self.grace_until > at
        # Rows created by an older version of the application may not have
        # the explicit window.  Derive it from the creation time so they
        # still get the same finite compatibility behavior.
        from .backends.db import get_rotation_grace_seconds

        return self.created_at + timedelta(
            seconds=get_rotation_grace_seconds()
        ) > at

    def as_dict(self):
        return {
            'old_session_key': self.old_session_key,
            'old_key': self.old_session_key,
            'new_session_key': self.new_session_key,
            'new_key': self.new_session_key,
            'user': self.user_id,
            'user_id': self.user_id,
            'user_version': self.user_version,
            'outcome': self.outcome,
            'phase': self.phase,
            'stage': self.stage,
            'rejection_phase': self.rejection_phase,
            'detail': self.detail,
        }

    @property
    def report(self):
        return self.as_dict()

    @classmethod
    def for_key(cls, session_key):
        return cls.objects.for_key(session_key)


# The same durable object is exposed under the names used by older callers
# and by operators who think in terms of audit events.  Keeping aliases means
# code can query a single source of truth without depending on a particular
# naming convention.
SessionKeyRotation = SessionRotation
SessionRotationEvent = SessionRotation
SessionKeyRotationEvent = SessionRotation
SessionRotationAudit = SessionRotation
SessionRotationRecord = SessionRotation
SessionAudit = SessionRotation
SessionAuditEvent = SessionRotation
SessionKeyAudit = SessionRotation
SessionRotationLog = SessionRotation
AnonymousSessionRotation = SessionRotation
AnonymousSessionMigration = SessionRotation
SessionMigration = SessionRotation
SessionRebindAudit = SessionRotation
SessionKeyRebind = SessionRotation
AnonymousAuthRebind = SessionRotation


@receiver(post_delete, sender=Session)
def _revoke_mappings_for_deleted_session(sender, instance, using, **kwargs):
    """
    Make every deletion path invalidate old-key compatibility links.

    This covers queryset/admin/background deletions that do not go through
    SessionStore.delete().  During a rotation of A -> B the signal may mark
    older mappings revoked just before the rotation code advances them to B;
    the later atomic update is authoritative.
    """
    if getattr(instance, '_rotation_consumed', False):
        return
    now = timezone.now()
    deleted_phase = (
        SessionRotation.STAGE_EXPIRED
        if instance.expire_date <= now
        else SessionRotation.STAGE_LOGOUT
    )
    SessionRotation.objects.using(using).filter(
        new_session_key=instance.pk,
    ).update(
        outcome=SessionRotation.OUTCOME_REVOKED,
        phase=SessionRotation.PHASE_REVOKED,
        stage=deleted_phase,
        rejection_phase=deleted_phase,
        rejected_at=now,
        detail='session row deleted outside the store',
        updated_at=now,
    )
