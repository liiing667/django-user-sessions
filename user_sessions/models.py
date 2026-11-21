from django.conf import settings
from django.contrib.sessions.base_session import (
    AbstractBaseSession, BaseSessionManager,
)
from django.db import models

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

    objects = SessionManager()

    # Used in get_decoded
    @classmethod
    def get_session_store_class(cls):
        return SessionStore


class SessionRevocationEvent(models.Model):
    """
    Immutable, per-device audit record for a batch session revocation.

    One row is written for every device each time a revocation batch touches
    (or deliberately skips) it. Because the rows are persisted and never
    overwritten, the outcome of a batch stays recoverable after retries and
    process restarts: the latest event for a given ``(batch_id,
    session_key)`` is the authoritative outcome, and the whole sequence of
    rows explains how that outcome was reached.
    """

    #: The device kept access to its data (e.g. current/expired session).
    OUTCOME_RETAINED = 'retained'
    #: The device's session row was deleted and access was revoked.
    OUTCOME_REVOKED = 'revoked'
    #: Revocation was attempted but could not be completed.
    OUTCOME_FAILED = 'failed'

    #: The session was looked up / reconciled before touching it.
    STAGE_QUERY = 'query'
    #: The DELETE of the session row was executed.
    STAGE_DELETE = 'delete'
    #: The deletion was committed inside its savepoint.
    STAGE_COMMIT = 'commit'

    OUTCOME_CHOICES = (
        (OUTCOME_RETAINED, 'Retained'),
        (OUTCOME_REVOKED, 'Revoked'),
        (OUTCOME_FAILED, 'Failed'),
    )
    STAGE_CHOICES = (
        (STAGE_QUERY, 'Query'),
        (STAGE_DELETE, 'Delete'),
        (STAGE_COMMIT, 'Commit'),
    )

    batch_id = models.CharField(max_length=64, db_index=True)
    session_key = models.CharField(max_length=40, db_index=True)
    outcome = models.CharField(max_length=16, choices=OUTCOME_CHOICES)
    stage = models.CharField(max_length=16, choices=STAGE_CHOICES)
    detail = models.CharField(max_length=255, blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ('id',)
        indexes = [
            models.Index(fields=['batch_id', 'session_key']),
        ]

    def __str__(self):
        return f'{self.session_key}: {self.outcome} at {self.stage} ({self.batch_id})'

    @property
    def is_revoked(self):
        return self.outcome == self.OUTCOME_REVOKED

    @property
    def is_retained(self):
        return self.outcome == self.OUTCOME_RETAINED

    @property
    def is_failed(self):
        return self.outcome == self.OUTCOME_FAILED
