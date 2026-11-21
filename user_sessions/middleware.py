from django.conf import settings
from django.contrib.sessions.middleware import (
    SessionMiddleware as DjangoSessionMiddleware,
)


class SessionMiddleware(DjangoSessionMiddleware):
    """
    Middleware that provides ip and user_agent to the session store.
    """
    def process_request(self, request):
        session_key = request.COOKIES.get(settings.SESSION_COOKIE_NAME, None)
        request.session = self.SessionStore(
            ip=request.META.get('REMOTE_ADDR', ''),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            session_key=session_key
        )

    def process_response(self, request, response):
        response = super().process_response(request, response)
        session = getattr(request, 'session', None)
        if session is not None and getattr(session, '_invalidated', False):
            # A late response must not put a deleted or rotated key back into
            # the browser. The server-side row is already gone, and issuing
            # the old cookie again would make every following request look
            # like a fresh invalid session.
            response.delete_cookie(
                settings.SESSION_COOKIE_NAME,
                path=settings.SESSION_COOKIE_PATH,
                domain=settings.SESSION_COOKIE_DOMAIN,
            )
        return response
