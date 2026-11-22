from django.conf import settings
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, resolve_url
from django.urls import reverse_lazy
from django.utils.decorators import method_decorator
from django.utils.timezone import now
from django.views.generic import ListView, View
from django.views.generic.detail import BaseDetailView
from django.views.generic.edit import DeletionMixin

from .revocation import SessionRevocationReport, revoke_sessions


class SessionMixin:
    """
    Mixin selecting the requesting user's active sessions.

    The request identity -- the requesting user, the current device and
    the target session -- is frozen as soon as the request enters the
    view, so the list selection, the ownership re-check and the delete
    submission all operate on the same objects. A concurrent request
    that re-authenticates or expires this session can therefore not
    smuggle a cross-user identifier into the queryset.
    """
    def dispatch(self, request, *args, **kwargs):
        # Freeze the request identity before anything else touches it.
        self.request_user = request.user
        self.current_session_key = request.session.session_key
        self.target_session_key = kwargs.get('pk')
        return super().dispatch(request, *args, **kwargs)

    def get_request_user(self):
        """The frozen requesting user, falling back to ``request.user``."""
        user = getattr(self, 'request_user', None)
        return self.request.user if user is None else user

    def get_current_session_key(self):
        """The frozen current device, falling back to the live session."""
        key = getattr(self, 'current_session_key', None)
        return self.request.session.session_key if key is None else key

    def get_target_session_key(self):
        """The frozen target session, falling back to the URL kwarg."""
        key = getattr(self, 'target_session_key', None)
        if key is None:
            key = getattr(self, 'kwargs', {}).get('pk')
        return key

    def get_queryset(self):
        return self.get_request_user().session_set\
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


class SessionDeleteView(LoginRequiredMixin, SessionMixin, DeletionMixin, BaseDetailView):
    """
    View for deleting a user's own session.

    This view allows a user to delete an active session. For example log
    out a session from a computer at the local library or a friend's place.

    The target session is frozen when the request enters the view and its
    ownership is re-checked against the frozen selection right before the
    deletion is submitted, so a session that another request re-assigned
    to a different user -- or that expired in the meantime -- can never
    be revoked through a stale list snapshot.
    """
    def delete(self, request, *args, **kwargs):
        session_key = self.get_target_session_key()
        if session_key == self.get_current_session_key():
            logout(request)
            next_page = getattr(settings, 'LOGOUT_REDIRECT_URL', '/')
            response = redirect(resolve_url(next_page))
            self.revocation_report = SessionRevocationReport(
                revoked=[session_key])
            response.revocation_report = self.revocation_report
            return response
        # Ownership re-check on the frozen selection: a session that does
        # not belong to the requesting user, is anonymous or has expired
        # yields a 404, exactly as before.
        self.object = self.get_object()
        self.revocation_report = revoke_sessions(
            self.get_request_user(),
            [session_key],
            current_session_key=self.get_current_session_key(),
        )
        response = redirect(self.get_success_url())
        response.revocation_report = self.revocation_report
        return response

    def get_success_url(self):
        return str(reverse_lazy('user_sessions:session_list'))


class SessionDeleteOtherView(LoginRequiredMixin, SessionMixin, DeletionMixin, View):
    """
    View for deleting all user's sessions but the current.

    This view allows a user to delete all other active session. For example
    log out all sessions from a computer at the local library or a friend's
    place.

    The list snapshot frozen when the request entered the view is
    submitted to :func:`~user_sessions.revocation.revoke_sessions`, which
    re-checks the ownership of every row and classifies each selected
    session as kept (the current device and any anonymous session),
    revoked or expired. The report is available as ``revocation_report``
    on the view and on the response, keyed by stable session identity so
    it stays valid for consumers running after a restart.
    """
    def get_object(self):
        return super().get_queryset().\
            exclude(session_key=self.get_current_session_key())

    def delete(self, request, *args, **kwargs):
        user = self.get_request_user()
        # The frozen list snapshot: every session of the requesting user.
        # revoke_sessions re-checks ownership of every row, so a
        # cross-user identifier can never race into the deletion.
        snapshot = user.session_set.values_list('session_key', flat=True)
        self.revocation_report = revoke_sessions(
            user,
            snapshot,
            current_session_key=self.get_current_session_key(),
        )
        response = redirect(self.get_success_url())
        response.revocation_report = self.revocation_report
        return response

    def get_success_url(self):
        return str(reverse_lazy('user_sessions:session_list'))
