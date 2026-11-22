from django.utils import timezone


def now():
    """
    Return the current time.

    This is the single clock shared by the session expiry bound, request
    renewal and the session list consumers, so they always agree on what
    "now" means. Clock jumps (e.g. after suspending and resuming a machine,
    or after a restart) are observed consistently by all of them.
    """
    return timezone.now()
