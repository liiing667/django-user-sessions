from django.db import router, transaction
from django.db.models import F


def get_session_generation(user, using=None):
    """
    Return the current session generation for ``user``.

    Users that never had their sessions invalidated have the initial
    generation of 1.
    """
    from ..models import UserSessionGeneration

    using = using or router.db_for_read(UserSessionGeneration)
    generation = UserSessionGeneration.objects.using(using) \
        .filter(user=user).values_list('generation', flat=True).first()
    return generation if generation is not None else 1


def invalidate_user_sessions(user, keep_session_keys=(), using=None):
    """
    Invalidate all sessions of ``user``, except those in ``keep_session_keys``.

    The user's session generation is bumped and all of the user's other
    sessions are deleted, so any pre-existing session is rejected on the next
    request. Call this in the same ``transaction.atomic()`` block as the
    credential change (e.g. a password reset or role revocation) to make the
    invalidation atomic with that write.

    Returns the new session generation.
    """
    from ..models import Session, UserSessionGeneration

    using = using or router.db_for_write(UserSessionGeneration)
    keep_session_keys = list(keep_session_keys)
    with transaction.atomic(using=using):
        generation_row, _ = UserSessionGeneration.objects.using(using) \
            .select_for_update().get_or_create(user=user)
        generation_row.generation = F('generation') + 1
        generation_row.save(update_fields=['generation'])
        generation_row.refresh_from_db(fields=['generation'])

        sessions = Session.objects.using(using).filter(user=user)
        sessions.exclude(session_key__in=keep_session_keys).delete()
        if keep_session_keys:
            sessions.filter(session_key__in=keep_session_keys) \
                .update(session_generation=generation_row.generation)

    return generation_row.generation
