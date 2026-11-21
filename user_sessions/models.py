from django.conf import settings
from django.contrib.sessions.base_session import (
    AbstractBaseSession, BaseSessionManager,
)
from django.db import models

from .backends.db import SessionStore


class SessionManager(BaseSessionManager):
    use_in_migrations = True


class UserSessionGeneration(models.Model):
    """
    Per-user session generation counter.

    Bumping the generation (see
    ``user_sessions.utils.invalidate_user_sessions``) invalidates all of the
    user's sessions that were stored with an older generation. Because the
    counter lives in the same database as the user data, the invalidation can
    be committed atomically together with e.g. a password reset or a role
    revocation.
    """
    user = models.OneToOneField(getattr(settings, 'AUTH_USER_MODEL', 'auth.User'),
                                primary_key=True,
                                related_name='session_generation',
                                on_delete=models.CASCADE)
    generation = models.PositiveIntegerField(default=1)

    def __str__(self):
        return f'{self.user_id}: {self.generation}'


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
    session_generation = models.PositiveIntegerField(default=1)

    objects = SessionManager()

    # Used in get_decoded
    @classmethod
    def get_session_store_class(cls):
        return SessionStore
