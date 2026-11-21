from django.conf import settings
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, resolve_url
from django.urls import reverse_lazy
from django.utils.decorators import method_decorator
from django.utils.timezone import now
from django.views.generic import ListView, View
from django.views.generic.detail import BaseDetailView

from .revocation import revoke_sessions


class SessionMixin:
    def get_queryset(self):
        return self.request.user.session_set\
            .filter(expire_date__gt=now()).order_by('-last_activity')


class LoginRequiredMixin:
    @method_decorator(login_required)
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)


class SessionListView(LoginRequiredMixin, SessionMixin, ListView):
    """
    View for listing a user's own sessions.

    This view shows list of a user's currently active sessions. You can
    override the template by providing your own template at
    `user_sessions/session_list.html`.
    """
    def get_context_data(self, **kwargs):
        kwargs['session_key'] = self.request.session.session_key
        return super().get_context_data(**kwargs)


class SessionDeleteView(LoginRequiredMixin, SessionMixin, BaseDetailView):
    """
    View for deleting a user's own session.

    This view allows a user to delete an active session. For example log
    out a session from a computer at the local library or a friend's place.

    The deletion is performed by the auditable
    :func:`user_sessions.revocation.revoke_sessions` service, so the result
    is deterministic and a per-device audit trail is stored even if a later
    bulk operation partially fails.
    """
    def delete(self, request, *args, **kwargs):
        session_key = kwargs['pk']
        if session_key == request.session.session_key:
            logout(request)
            next_page = getattr(settings, 'LOGOUT_REDIRECT_URL', '/')
            return redirect(resolve_url(next_page))
        # Preserve the previous BaseDetailView semantics: a session that does
        # not belong to the user (or is expired / unknown) yields a 404 and
        # never produces a misleading audit row.
        self.get_object()
        # Scoped through the owner-filtered, expiry-aware queryset: foreign
        # or expired keys cannot be touched and are simply not found.
        self.revocation_report = revoke_sessions(
            self.get_queryset(),
            [session_key],
            current_session_key=request.session.session_key,
        )
        return redirect(self.get_success_url())

    def get_success_url(self):
        return str(reverse_lazy('user_sessions:session_list'))


class SessionDeleteOtherView(LoginRequiredMixin, SessionMixin, View):
    """
    View for deleting all user's sessions but the current.

    This view allows a user to delete all other active session. For example
    log out all sessions from a computer at the local library or a friend's
    place.

    Instead of a single bulk ``QuerySet.delete()`` — which gives no way to
    tell which devices were actually revoked once the response fails — each
    device is revoked independently by
    :func:`user_sessions.revocation.revoke_sessions`. The resulting
    :class:`~user_sessions.revocation.SessionRevocationReport` is attached to
    the response as ``revocation_report`` and remains reconstructable from
    the database after retries or restarts.
    """
    def post(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        other_keys = queryset.exclude(
            session_key=request.session.session_key,
        ).values_list('session_key', flat=True)
        self.revocation_report = revoke_sessions(
            queryset,
            other_keys,
            current_session_key=request.session.session_key,
        )
        return redirect(self.get_success_url())

    def get_success_url(self):
        return str(reverse_lazy('user_sessions:session_list'))
