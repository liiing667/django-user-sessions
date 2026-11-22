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


Revoking sessions
-----------------
The session list is a snapshot: by the time a delete request is submitted,
another request may have re-authenticated one of the listed sessions to a
different user or let it expire. The delete views therefore freeze the
requesting user, the current device and the target session as soon as the
request enters the view, and re-check the ownership of every selected
session right before it is deleted. A cross-user identifier can never race
into the queryset, the current device and all anonymous sessions are always
preserved, and expired sessions stay filtered out.

The outcome is classified as kept / revoked / expired and is keyed by
session key -- the stable identity of a device -- so consumers running
after a restart observe the same object identity::

    from user_sessions.revocation import revoke_sessions

    report = revoke_sessions(user, ['SESSION-KEY'], current_session_key='CURRENT')
    report.kept_session_keys     # current device, anonymous and foreign sessions
    report.revoked_session_keys  # sessions that were actually deleted
    report.expired_session_keys  # sessions that had already expired

The delete views expose the same report as ``revocation_report`` on the
view and on the redirect response.

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
