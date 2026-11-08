"""Private feedback: authenticated encryption, separate keys, bounded shared quotas."""
import os
import time
from pathlib import Path
from datetime import datetime, timezone

from cryptography.fernet import Fernet, MultiFernet
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.db import transaction
from django.db.models import F
from django.utils.crypto import salted_hmac
from django.views.decorators.debug import sensitive_variables

from .models import AdminLoginThrottle


class _QuotaExceeded(Exception):
    pass


@sensitive_variables()
def feedback_cipher():
    keys = list(settings.FEEDBACK_ENCRYPTION_KEYS)
    if not keys and settings.FEEDBACK_ENCRYPTION_KEY_FILE:
        path = Path(settings.FEEDBACK_ENCRYPTION_KEY_FILE).resolve()
        public_roots = [settings.MEDIA_ROOT, settings.BASE_DIR / 'static', settings.STATIC_ROOT]
        if any(path.is_relative_to(Path(root).resolve()) for root in public_roots):
            raise ImproperlyConfigured('Feedback keys must stay outside public directories.')
        try:
            keys = [path.read_bytes().strip()]
        except OSError:
            raise ImproperlyConfigured('Cannot read configured feedback encryption key.') from None
    if not keys:
        if settings.IS_PRODUCTION:
            raise ImproperlyConfigured('Configure FEEDBACK_ENCRYPTION_KEYS separately from the database.')
        path = settings.DATA_DIR / '.feedback-key'
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        except OSError:
            raise ImproperlyConfigured('Cannot create local feedback encryption key.') from None
        else:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(Fernet.generate_key())
        try:
            keys = [path.read_bytes().strip()]
        except OSError:
            raise ImproperlyConfigured('Cannot read local feedback encryption key.') from None
    try:
        return MultiFernet([Fernet(key) for key in keys])
    except (ValueError, TypeError):
        raise ImproperlyConfigured('Invalid feedback encryption key configuration.') from None


def take_feedback_quota(ip):
    now = int(time.time())
    # REMOTE_ADDR only: forwarded headers from visitors are not trusted.
    try:
        with transaction.atomic():
            for scope, identity, window, limit in (
                ('global', 'all', 3600, settings.FEEDBACK_GLOBAL_LIMIT),
                ('ip', ip, 600, settings.FEEDBACK_IP_LIMIT),
            ):
                key = salted_hmac('private-feedback', f'{scope}:{identity}:{now // window}', algorithm='sha256').hexdigest()
                AdminLoginThrottle.objects.get_or_create(
                    key=key, defaults={'expires_at': datetime.fromtimestamp((now // window + 1) * window, timezone.utc)},
                )
                if not AdminLoginThrottle.objects.filter(key=key, attempts__lt=limit).update(attempts=F('attempts') + 1):
                    # Roll back both counters, including newly-created rows.
                    raise _QuotaExceeded
    except _QuotaExceeded:
        return False
    return True
