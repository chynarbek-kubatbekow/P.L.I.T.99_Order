import logging
import os

from django.db.backends.signals import connection_created
from django.dispatch import receiver

logger = logging.getLogger(__name__)


@receiver(connection_created)
def configure_sqlite_connection(sender, connection, **kwargs):
    if connection.vendor != 'sqlite':
        return

    requested_journal_mode = os.getenv('SQLITE_JOURNAL_MODE', 'WAL').strip().upper() or 'WAL'
    if requested_journal_mode not in {'WAL', 'DELETE', 'TRUNCATE', 'PERSIST'}:
        requested_journal_mode = 'WAL'

    with connection.cursor() as cursor:
        cursor.execute('PRAGMA foreign_keys = ON;')

        # Some hosted disks do not behave well with WAL/shm files.
        # Fall back to DELETE mode so the app can still boot reliably.
        try:
            actual_mode = cursor.execute(
                f'PRAGMA journal_mode = {requested_journal_mode};'
            ).fetchone()[0].upper()
        except Exception as exc:
            logger.warning(
                'Could not enable SQLite journal mode %s: %s. Falling back to DELETE.',
                requested_journal_mode,
                exc,
            )
            actual_mode = cursor.execute('PRAGMA journal_mode = DELETE;').fetchone()[0].upper()

        if actual_mode != requested_journal_mode:
            logger.warning(
                'SQLite journal mode requested=%s, actual=%s. Continuing with %s.',
                requested_journal_mode,
                actual_mode,
                actual_mode,
            )

        cursor.execute('PRAGMA synchronous = NORMAL;')
        cursor.execute('PRAGMA temp_store = MEMORY;')
        cursor.execute('PRAGMA cache_size = -20000;')
