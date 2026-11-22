"""
Accurate revocation of sessions selected from the session list.

The session list is a snapshot: by the time the delete request is
submitted, another request may have re-authenticated one of the listed
sessions to a different user or let it expire. Acting on the stale
snapshot must never delete a row that no longer belongs to the
requesting user.

This module performs the revocation against a *frozen* identity:

* the requesting ``user`` is captured when the list selection is made,
  so a cross-user identifier cannot race into the queryset;
* the ``current_session_key`` -- the device issuing the request -- is
  always kept, and anonymous sessions (which never belong to any user)
  are never touched;
* ownership of every selected session is re-checked right before it is
  deleted, and expired rows are left for ``clearsessions``, exactly as
  the expiry-filtered list queryset skips them.

The outcome is reported as a :class:`SessionRevocationReport` keyed by
session key -- the stable identity of a device -- so the list
selection, the ownership re-check, the delete submission and any
consumer running after a restart all observe the same object identity,
classified as *kept*, *revoked* or *expired*.
"""
from django.utils.timezone import now

__all__ = ['SessionRevocationReport', 'revoke_sessions']


class SessionRevocationReport:
    """
    Outcome of a revocation request, classified by stable session identity.

    Every submitted session key ends up in exactly one category:

    * ``kept_session_keys`` -- sessions that were deliberately preserved:
      the current device and any anonymous, foreign or unknown session,
      none of which may ever be revoked on behalf of the requesting user;
    * ``revoked_session_keys`` -- sessions that were actually deleted;
    * ``expired_session_keys`` -- sessions that had already expired and
      were left untouched, exactly as the expiry-filtered list queryset
      would have skipped them.
    """
    def __init__(self, kept=(), revoked=(), expired=()):
        self.kept_session_keys = frozenset(kept)
        self.revoked_session_keys = frozenset(revoked)
        self.expired_session_keys = frozenset(expired)

    @property
    def session_keys(self):
        """Every session key that was submitted for revocation."""
        return (self.kept_session_keys | self.revoked_session_keys |
                self.expired_session_keys)

    @property
    def summary(self):
        """The three result categories with their sizes."""
        return {
            'kept': len(self.kept_session_keys),
            'revoked': len(self.revoked_session_keys),
            'expired': len(self.expired_session_keys),
        }

    def __len__(self):
        return len(self.session_keys)

    def __eq__(self, other):
        if not isinstance(other, SessionRevocationReport):
            return NotImplemented
        return (self.kept_session_keys == other.kept_session_keys and
                self.revoked_session_keys == other.revoked_session_keys and
                self.expired_session_keys == other.expired_session_keys)

    def __repr__(self):
        return (
            f'SessionRevocationReport(kept={sorted(self.kept_session_keys)}, '
            f'revoked={sorted(self.revoked_session_keys)}, '
            f'expired={sorted(self.expired_session_keys)})'
        )


def revoke_sessions(user, session_keys, current_session_key=None):
    """
    Revoke ``session_keys`` on behalf of ``user`` and classify the outcome.

    ``user`` is the frozen requesting user, ``session_keys`` the frozen
    list selection and ``current_session_key`` the frozen current device.
    Ownership of every row is re-checked against ``user`` at deletion
    time, so a session that another request re-authenticated to a
    different user -- or an anonymous session -- can never be revoked
    through a stale list snapshot.

    Returns a :class:`SessionRevocationReport` with the kept / revoked /
    expired classification.
    """
    # De-duplicate while keeping the submission order deterministic.
    keys = list(dict.fromkeys(session_keys))
    # Ownership re-check: only rows still owned by the frozen user are
    # eligible. Anonymous sessions (``user=None``) and other users'
    # sessions can never race into this queryset.
    owned = {
        session.session_key: session
        for session in user.session_set.filter(session_key__in=keys)
    }
    kept, revoked, expired = [], [], []
    for key in keys:
        if key == current_session_key:
            # The current device is always preserved.
            kept.append(key)
        elif key not in owned:
            # Anonymous, foreign or unknown session: never revoked.
            kept.append(key)
        elif owned[key].expire_date <= now():
            # Already expired: filtered out, left for ``clearsessions``.
            expired.append(key)
        else:
            owned[key].delete()
            revoked.append(key)
    return SessionRevocationReport(kept=kept, revoked=revoked, expired=expired)
