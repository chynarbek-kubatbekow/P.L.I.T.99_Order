import os
from pathlib import Path

from cryptography.fernet import Fernet
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = 'Create a separate feedback encryption key without printing or replacing it.'

    def handle(self, *args, **options):
        configured = settings.FEEDBACK_ENCRYPTION_KEY_FILE
        if settings.IS_PRODUCTION and not configured:
            raise CommandError('Set FEEDBACK_ENCRYPTION_KEY_FILE to a private absolute path first.')
        path = Path(configured).resolve() if configured else settings.DATA_DIR / '.feedback-key'
        if not path.is_absolute() or any(path.is_relative_to(Path(root).resolve()) for root in (settings.MEDIA_ROOT, settings.BASE_DIR / 'static', settings.STATIC_ROOT)):
            raise CommandError('Choose a private path outside media/static.')
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(Fernet.generate_key())
        except FileExistsError:
            raise CommandError('Key already exists; it was not changed.') from None
        except OSError:
            raise CommandError('Cannot create key at the configured private path.') from None
        self.stdout.write(self.style.SUCCESS('Feedback key created. Value was not printed. Back it up separately from the database.'))
