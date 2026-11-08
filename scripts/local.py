"""Local management/preview profile; never writes or weakens production .env."""
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parent.parent


def main():
    os.chdir(ROOT)
    sys.path.insert(0, str(ROOT))
    # Optional local config overrides .env only in this child process. Loading
    # the existing file preserves the current data directory, users and keys.
    for env_file in (ROOT / '.env', ROOT / '.env.local'):
        if not env_file.is_file():
            continue
        for line in env_file.read_text(encoding='utf-8-sig').splitlines():
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            name, value = line.split('=', 1)
            name, value = name.strip(), value.strip()
            if not name.isidentifier():
                raise SystemExit('Invalid environment variable name in local configuration.')
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
                value = value[1:-1]
            os.environ[name] = value
    os.environ.update({
        'APP_ENV': 'local', 'LOCAL_PREVIEW': 'True', 'DEBUG': 'False',
        'SECURE_SSL_REDIRECT': 'False', 'SESSION_COOKIE_SECURE': 'False',
        'CSRF_COOKIE_SECURE': 'False', 'SECURE_HSTS_SECONDS': '0',
        'SECURE_HSTS_INCLUDE_SUBDOMAINS': 'False', 'SECURE_HSTS_PRELOAD': 'False',
        'TRUST_PROXY_HEADERS': 'False', 'ALLOWED_HOSTS': '127.0.0.1,localhost,[::1]',
        'CSRF_TRUSTED_ORIGINS': 'http://127.0.0.1:8001,http://localhost:8001',
        'DJANGO_SETTINGS_MODULE': 'plit99_project.settings',
    })
    os.environ.pop('MIGRATION_DATABASE_URL', None)
    command = sys.argv[1:] or ['runserver', '127.0.0.1:8001']
    if command[0] == 'runserver':
        address = next((arg for arg in command[1:] if not arg.startswith('-')), '127.0.0.1:8000')
        if ':' in address and address.rsplit(':', 1)[0] not in {'127.0.0.1', 'localhost', '[::1]'}:
            raise SystemExit('Local preview must bind to loopback; use start.sh/start.ps1 for deployment.')
        if os.getenv('RUN_MAIN') != 'true':
            print('Local HTTP preview only; production configuration is unchanged.', flush=True)
            print('Default site: http://127.0.0.1:8001/contacts/', flush=True)
            print('Default admin: http://127.0.0.1:8001/admin/', flush=True)
    from django.core.management import execute_from_command_line
    execute_from_command_line([str(ROOT / 'manage.py'), *command])


if __name__ == '__main__':
    main()
