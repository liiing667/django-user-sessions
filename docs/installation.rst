Installation
============
1. ``pip install django-user-sessions``
2. In ``INSTALLED_APPS`` replace ``'django.contrib.sessions'`` with
   ``'user_sessions'``.
3. In ``MIDDLEWARE`` or ``MIDDLEWARE_CLASSES`` replace
   ``'django.contrib.sessions.middleware.SessionMiddleware'`` with
   ``'user_sessions.middleware.SessionMiddleware'``.
4. Add ``SESSION_ENGINE = 'user_sessions.backends.db'``.
5. Add ``url(r'', include('user_sessions.urls', 'user_sessions')),`` to your
   ``urls.py``.
6. Make sure ``LOGOUT_REDIRECT_URL`` is set to some page to redirect users
   after logging out.
7. Run ``python manage.py syncdb`` (or ``migrate``) and browse to
   ``/account/sessions/``.

Limiting active sessions
------------------------
By default there is no limit on the number of sessions a single user can have
active at the same time. Set ``SESSION_ACTIVE_LIMIT`` in your settings file to
a positive integer to cap the number of active (non-expired) sessions per
user::

    SESSION_ACTIVE_LIMIT = 5

When a new authenticated session is created and the user already has the
maximum number of active sessions, the oldest active session(s) of that user
are evicted atomically, so the limit is never exceeded even when sessions are
created concurrently. Anonymous sessions are not limited. A missing setting
or any non-positive value disables the limit.

System check framework
----------------------

Django warns you about common configuration errors. When replacing the session
middleware with the one provided by this library, it'll start warning about
`admin.E410`. You can silence this warning by adding the following line in
your settings file:

``SILENCED_SYSTEM_CHECKS = ['admin.E410']``


GeoIP
-----
You need to setup GeoIP for the location detection to work. See the Django
documentation on `installing GeoIP`_.

IP when behind a proxy
----------------------
If you're running Django behind a proxy like nginx, you will have to set
the `REMOTE_ADDR` META header manually using a middleware, to stop it from
always returning the ip of the proxy (e.g. 127.0.0.1 in many cases).

An example middleware to fix this issue is `django-xforwardedfor-middleware`_
which simply does this for each request:

``request.META['REMOTE_ADDR'] = request.META['HTTP_X_FORWARDED_FOR'].split(',')[0].strip()``

Your particular configuration may vary, `X-Forwarded-For` must be set by
a proxy that you have control over, otherwise it might be spoofed by the
client.

.. _installing GeoIP:
   https://docs.djangoproject.com/en/1.11/ref/contrib/gis/geoip2/

.. _django-xforwardedfor-middleware:
   https://github.com/allo-/django-xforwardedfor-middleware
