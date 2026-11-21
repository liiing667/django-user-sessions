import importlib
import logging

from django.contrib import auth
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.db import transaction

from user_sessions.backends.db import SessionStore
from user_sessions.models import Session as UserSession

logger = logging.getLogger(__name__)


def get_model_class(full_model_name):
    try:
        old_model_package, old_model_class_name = full_model_name.rsplit('.', 1)
        package = importlib.import_module(old_model_package)
        return getattr(package, old_model_class_name)
    except RuntimeError as e:
        if 'INSTALLED_APPS' in str(e):
            raise RuntimeError(
                "To run this command, temporarily append '{model}' to settings.INSTALLED_APPS"
                .format(model=old_model_package.rsplit('.models')[0]))
        raise


class Command(BaseCommand):
    """
    Convert existing (old) sessions to the user_sessions SessionStore.

    If you have an operational site and switch to user_sessions, you might want to keep your
    active users logged in. We assume the old sessions are stored in a database table `oldmodel`.
    This command creates a `user_session.Session` object for each session of the previous model.

    The conversion is all-or-nothing: the source sessions are snapshotted up-front -- freezing
    each session's provenance (source model and verbatim, still-signed payload) and primary key
    identity -- and the new rows are published in a single transaction. A concurrent collision
    or a failure halfway through can therefore never expose a partially converted batch to
    incoming requests. The source sessions are left untouched as evidence, so the command can
    simply be re-run after a failure; already converted sessions are skipped.
    """
    def add_arguments(self, parser):
        parser.add_argument(
            '--oldmodel',
            dest='oldmodel',
            default='django.contrib.sessions.models.Session',
            help='Existing session model to migrate to the new UserSessions database table'
        )

    def handle(self, *args, **options):
        User = get_user_model()
        old_model = get_model_class(options['oldmodel'])
        source = options['oldmodel']

        # Freeze the batch before publishing anything: snapshot every source session's primary
        # key identity and (verbatim, still-signed) payload as provenance evidence. Concurrent
        # writes to the source table can no longer change what this run imports, and a failed
        # run can be retried with the same frozen batch. The payload is decoded with the
        # tolerant session store, so legitimately old serialization formats remain readable.
        store = SessionStore()
        batch = []
        for old_session in old_model.objects.all().iterator():
            data = store.decode(old_session.session_data)
            batch.append({
                'session_key': old_session.session_key,
                'session_data': old_session.session_data,
                'expire_date': old_session.expire_date,
                'user_id': data.get(auth.SESSION_KEY),
            })
        logger.info("Processing %d session objects from %s", len(batch), source)

        # Publish the batch atomically: either every remaining session is converted or none of
        # them are. get_or_create() turns a concurrent creation of the same session key into a
        # no-op instead of an IntegrityError, and leaves the existing row untouched.
        conversion_count = 0
        with transaction.atomic():
            for frozen in batch:
                user = None
                if frozen['user_id'] is not None:
                    user = User.objects.filter(pk=frozen['user_id']).first()
                _, created = UserSession.objects.get_or_create(
                    session_key=frozen['session_key'],
                    defaults={
                        'session_data': frozen['session_data'],
                        'expire_date': frozen['expire_date'],
                        'user': user,
                        'ip': '127.0.0.1',
                    },
                )
                conversion_count += int(created)

        logger.info("Created %d new session objects", conversion_count)
