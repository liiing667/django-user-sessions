"""
Deterministic batch revocation of user sessions.

Deleting many sessions one-by-one is not atomic: a database error halfway
through leaves some devices revoked and others still active, and after a
retry or a process restart nobody can tell which devices still hold access.

This module makes the outcome *deterministic* and *auditable*:

* every device is processed inside its own savepoint, so a failure on one
  device never rolls back deletions already committed for earlier devices;
* every attempt appends an immutable
  :class:`~user_sessions.models.SessionRevocationEvent` row describing the
  device, the processing stage and the outcome (retained / revoked / failed);
* retries are idempotent — already-revoked devices are skipped and devices
  whose row vanished without an audit row are reconciled;
* the :class:`SessionRevocationReport` rebuilt from the stored rows gives the
  exact retained/revoked/failed sets and points at the precise stage and
  device of every failure, even after a restart.
"""
import uuid

from django.db import transaction
from django.utils.timezone import now

from .models import SessionRevocationEvent


# Test-only fault injection: {(stage, session_key): exception/callable}.
# Kept in one place so production code paths never have to branch on tests.
_FAULT_INJECTIONS = {}


def inject_failure(stage, session_key, error):
    """Make processing of ``session_key`` fail at ``stage`` (test helper)."""
    _FAULT_INJECTIONS[(stage, session_key)] = error


def clear_injected_failures():
    """Remove every injected failure (test helper)."""
    _FAULT_INJECTIONS.clear()


def _raise_if_fault(stage, session_key):
    fault = _FAULT_INJECTIONS.get((stage, session_key))
    if fault is None:
        return
    error = fault() if callable(fault) else fault
    # Tag the error so the except block can name the failing stage even
    # though the savepoint unwinds the surrounding context.
    try:
        error.revocation_stage = stage
    except (AttributeError, TypeError):
        pass
    raise error


def _record_event(batch_id, session_key, outcome, stage, detail=''):
    """Append an immutable audit row. Never updated or deleted."""
    return SessionRevocationEvent.objects.create(
        batch_id=batch_id,
        session_key=session_key,
        outcome=outcome,
        stage=stage,
        detail=detail[:255],
    )


class SessionRevocationReport:
    """
    Deterministic view over the audit rows of one revocation batch.

    The report is rebuilt from :class:`SessionRevocationEvent` rows rather
    than held in memory, so an identical report is available after a retry
    or a full process restart. The latest event per device is the
    authoritative outcome; the full row history remains available for the
    per-device audit explanation.
    """

    def __init__(self, batch_id):
        self.batch_id = batch_id
        self.events = list(
            SessionRevocationEvent.objects.filter(batch_id=batch_id)
        )
        latest = {}
        for event in self.events:
            # Events are ordered by id, so later rows overwrite earlier ones.
            latest[event.session_key] = event
        self._latest = latest

    def __repr__(self):
        return (
            f'SessionRevocationReport(batch_id={self.batch_id!r}, '
            f'revoked={len(self.revoked_session_keys)}, '
            f'retained={len(self.retained_session_keys)}, '
            f'failed={len(self.failed_session_keys)})'
        )

    @property
    def session_keys(self):
        """Every device that belongs to this batch, with its final outcome."""
        return set(self._latest)

    @property
    def revoked_session_keys(self):
        """Devices whose data access is definitively revoked."""
        return {
            key for key, event in self._latest.items() if event.is_revoked
        }

    @property
    def retained_session_keys(self):
        """Devices that deliberately kept access to their data."""
        return {
            key for key, event in self._latest.items() if event.is_retained
        }

    @property
    def failed_session_keys(self):
        """Devices whose revocation could not be completed."""
        return {
            key for key, event in self._latest.items() if event.is_failed
        }

    @property
    def failures(self):
        """
        Precise failure locations: one mapping per failed device with the
        ``session_key`` (device), processing ``stage`` and error ``detail``.
        """
        return [
            {
                'session_key': event.session_key,
                'stage': event.stage,
                'detail': event.detail,
            }
            for event in self._latest.values()
            if event.is_failed
        ]

    @property
    def summary(self):
        return {
            'batch_id': self.batch_id,
            'total': len(self._latest),
            'revoked': len(self.revoked_session_keys),
            'retained': len(self.retained_session_keys),
            'failed': len(self.failed_session_keys),
            'complete': not self.failed_session_keys,
        }

    def events_for(self, session_key):
        """Full audit trail (all attempts) for one device."""
        return [
            event for event in self.events
            if event.session_key == session_key
        ]

    def outcome_of(self, session_key):
        """Latest event for a device, or ``None`` if it is not in the batch."""
        return self._latest.get(session_key)


def revoke_sessions(session_queryset, session_keys, *, batch_id=None,
                    current_session_key=None, at=None):
    """
    Revoke the given sessions with a deterministic, auditable outcome.

    :param session_queryset: the queryset the devices must belong to, e.g.
        ``request.user.session_set.filter(expire_date__gt=now())``. Only
        rows reachable through this queryset can ever be deleted.
    :param session_keys: iterable of device session keys to revoke.
    :param batch_id: stable identifier shared by all attempts/retries of the
        same operation. A new UUID is generated when omitted.
    :param current_session_key: the caller's own session, which is never
        deleted (revoking it would log the operator out mid-operation); it is
        audited as ``retained`` instead.
    :param at: injectable "now" for the expiry reconciliation note.
    :returns: :class:`SessionRevocationReport` rebuilt from the stored audit
        rows.

    Each device is processed independently inside its own savepoint, so a
    failure only affects that device. Re-running the function with the same
    ``batch_id`` is safe: previously revoked devices are skipped, retained
    devices are re-evaluated and failed devices are retried.
    """
    if batch_id is None:
        batch_id = uuid.uuid4().hex
    if at is None:
        at = now()

    # Materialize once; duplicate keys must describe one device, not two.
    session_keys = list(dict.fromkeys(session_keys))

    # Reconstruct what previous attempts already decided, so retries and
    # restarts converge on the same final sets instead of diverging.
    previous = {
        event.session_key: event
        for event in SessionRevocationEvent.objects.filter(
            batch_id=batch_id,
            session_key__in=session_keys,
        )
    }

    for key in session_keys:
        prior = previous.get(key)

        # Idempotency: a device whose revocation was already committed stays
        # revoked and is never touched again on retry.
        if prior is not None and prior.is_revoked:
            continue

        # The operator's own session must survive the batch.
        if current_session_key is not None and key == current_session_key:
            if prior is None or not prior.is_retained:
                _record_event(
                    batch_id, key,
                    SessionRevocationEvent.OUTCOME_RETAINED,
                    SessionRevocationEvent.STAGE_QUERY,
                    'current session cannot be revoked in bulk',
                )
            continue

        try:
            _raise_if_fault(SessionRevocationEvent.STAGE_QUERY, key)
            session = session_queryset.filter(session_key=key).first()
        except Exception as exc:  # database was unreachable at query time
            _record_event(
                batch_id, key,
                SessionRevocationEvent.OUTCOME_FAILED,
                SessionRevocationEvent.STAGE_QUERY,
                f'{type(exc).__name__}: {exc}',
            )
            continue

        if session is None:
            # The row is already gone. Either an earlier attempt deleted it
            # before the process died (restart reconciliation), or it expired
            # and the existing clearsessions background job removed it. In
            # both cases the device no longer has data access, so the outcome
            # is "revoked" with an explanatory audit row.
            detail = (
                'session row absent at query stage; reconciled as revoked '
                f'(checked at {at.isoformat()})'
            )
            _record_event(
                batch_id, key,
                SessionRevocationEvent.OUTCOME_REVOKED,
                SessionRevocationEvent.STAGE_QUERY,
                detail,
            )
            continue

        try:
            # Per-device savepoint: a failure here cannot undo deletions
            # already committed for earlier devices in the same batch.
            with transaction.atomic():
                _raise_if_fault(SessionRevocationEvent.STAGE_DELETE, key)
                deleted, _ = session_queryset.filter(session_key=key).delete()
                _raise_if_fault(SessionRevocationEvent.STAGE_COMMIT, key)
        except Exception as exc:
            # The savepoint rolled back: the row still exists and the device
            # stays active. Record exactly where it broke so the report can
            # name the device and the stage.
            _record_event(
                batch_id, key,
                SessionRevocationEvent.OUTCOME_FAILED,
                getattr(exc, 'revocation_stage',
                        SessionRevocationEvent.STAGE_DELETE),
                f'{type(exc).__name__}: {exc}',
            )
            continue

        if deleted == 0:
            # Concurrent worker (or the clearsessions job) removed the row
            # between the query and the delete. Access is gone regardless.
            _record_event(
                batch_id, key,
                SessionRevocationEvent.OUTCOME_REVOKED,
                SessionRevocationEvent.STAGE_DELETE,
                'row removed concurrently before delete',
            )
        else:
            _record_event(
                batch_id, key,
                SessionRevocationEvent.OUTCOME_REVOKED,
                SessionRevocationEvent.STAGE_COMMIT,
                f'{deleted} session row(s) deleted',
            )

    return SessionRevocationReport(batch_id)
