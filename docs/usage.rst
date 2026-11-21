Usage
=====

Current session
---------------
The current session is available on the request, just like the normal session
middleware makes the session available::

    def my_view(request):
        request.session


All sessions
------------
To get the list of a user's sessions::

    sessions = user.session_set.filter(expire_date__gt=now())

You could logout the user everywhere::

    user.session_set.all().delete()

Deterministic batch revocation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
A plain ``QuerySet.delete()`` is a single bulk statement: when the database
fails halfway through, some devices are revoked while others stay active, and
after a retry or a process restart there is no way to tell which devices can
still access the user's data.

:func:`user_sessions.revocation.revoke_sessions` processes every device in
its own database savepoint and appends an immutable
:class:`~user_sessions.models.SessionRevocationEvent` audit row per attempt,
so the retained, revoked and failed sets are always recoverable::

    from user_sessions.revocation import revoke_sessions

    queryset = user.session_set.filter(expire_date__gt=now())
    report = revoke_sessions(
        queryset,
        queryset.values_list('session_key', flat=True),
    )

    report.revoked_session_keys   # devices whose access was revoked
    report.retained_session_keys  # devices deliberately kept (e.g. current)
    report.failed_session_keys    # devices that could not be revoked
    report.failures               # [{session_key, stage, detail}, ...]

Retries are idempotent: pass the same ``batch_id`` on every attempt and
already-revoked devices are skipped while failed devices are retried. A
:class:`~user_sessions.revocation.SessionRevocationReport` rebuilt from the
stored rows gives the same answer in another process, for example after a
restart. The bundled ``session_delete_other`` and ``session_delete`` views use
this service internally and expose the report as ``response.revocation_report``.


Generic views
-------------
There are two views included with this application,
:class:`~user_sessions.views.SessionListView` and
:class:`~user_sessions.views.SessionDeleteView`. Using this views you have a
simple, but effective, user session management that even looks great out of
the box:

.. image:: _static/custom-view.png

Template tags
~~~~~~~~~~~~~

- ``browser`` - used to get just
  the browser from a session
- ``platform`` - used to get just
  the operating system from a session
- ``device`` - used to get both
  the user's browser and the operating system from a session

    .. code-block:: html+django

        {% load user_sessions %}
        {{ session.user_agent|device }}   -> Safari on macOS
        {{ session.user_agent|browser }}  -> Safari
        {{ session.user_agent|platform }} -> macOS

- ``location`` - used to show an
  approximate location of the last IP address for a session

    .. code-block:: html+django

        {% load user_sessions %}
        {{ session.ip|location }} -> Zwolle, The Netherlands


Admin views
-----------

The user's IP address and user agent are also stored on the session. This
allows to show a list of active sessions to the user in the admin:

.. image:: _static/admin-view.png
