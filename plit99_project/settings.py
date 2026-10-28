import os
import secrets
import sys
from pathlib import Path

import dj_database_url
from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_RUNTIME_DATA_DIR = BASE_DIR / '.runtime-data'


def env_bool(name, default=False):
    return os.getenv(name, str(default)).strip().lower() in {'1', 'true', 'yes', 'on'}


def env_int(name, default=0):
    raw_value = os.getenv(name, '').strip()
    if raw_value:
        return int(raw_value)
    return int(default)


def env_list(name, default=''):
    return [item.strip() for item in os.getenv(name, default).split(',') if item.strip()]


def env_path(name, default):
    raw_value = os.getenv(name, '').strip()
    if raw_value:
        path = Path(raw_value)
        return path if path.is_absolute() else (BASE_DIR / path).resolve()
    return default


APP_ENV = os.getenv('APP_ENV', 'local').strip().lower()
if APP_ENV not in {'local', 'production'}:
    raise ImproperlyConfigured('APP_ENV must be local or production.')
IS_PRODUCTION = APP_ENV == 'production'
DEBUG = env_bool('DEBUG', False)
if IS_PRODUCTION and DEBUG:
    raise ImproperlyConfigured('DEBUG must be disabled in production.')


def ensure_runtime_dir(path):
    try:
        path.mkdir(parents=True, exist_ok=True)
        return path
    except OSError as exc:
        if IS_PRODUCTION:
            raise ImproperlyConfigured('Cannot access the production data directory.') from None
        print(
            f'Warning: cannot create runtime data dir {path}: {exc}. '
            f'Falling back to {DEFAULT_RUNTIME_DATA_DIR}.',
            file=sys.stderr,
        )
        DEFAULT_RUNTIME_DATA_DIR.mkdir(parents=True, exist_ok=True)
        return DEFAULT_RUNTIME_DATA_DIR


PUBLIC_STATIC_DIRS = (BASE_DIR / 'static', BASE_DIR / 'staticfiles')


def reject_public_data_path(path):
    resolved = Path(path).resolve()
    if any(resolved.is_relative_to(public.resolve()) for public in PUBLIC_STATIC_DIRS):
        raise ImproperlyConfigured('Runtime data and databases must stay outside public static directories.')


configured_data_dir = env_path('APP_DATA_DIR', DEFAULT_RUNTIME_DATA_DIR)
reject_public_data_path(configured_data_dir)
DATA_DIR = ensure_runtime_dir(configured_data_dir)

# A stable local key avoids invalidating sessions on every restart. Never generate
# an ephemeral production key or ship a development key in the source code.
SECRET_KEY = os.getenv('SECRET_KEY', '').strip()
if not SECRET_KEY:
    if IS_PRODUCTION:
        raise ImproperlyConfigured('SECRET_KEY is required in production.')
    key_path = DATA_DIR / '.secret-key'
    try:
        descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(descriptor, 'w', encoding='ascii') as key_file:
            key_file.write(secrets.token_urlsafe(64))
    SECRET_KEY = key_path.read_text(encoding='ascii').strip()
if len(SECRET_KEY) < 50 or len(set(SECRET_KEY)) < 5 or SECRET_KEY.startswith('django-insecure-'):
    raise ImproperlyConfigured('Configure a strong SECRET_KEY of at least 50 characters.')

ALLOWED_HOSTS = env_list('ALLOWED_HOSTS', '127.0.0.1,localhost')
if '*' in ALLOWED_HOSTS:
    raise ImproperlyConfigured('ALLOWED_HOSTS must list explicit hosts.')

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'core.apps.CoreConfig',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'core.middleware.SecurityHeadersMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'core.middleware.AdminLoginThrottleMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'plit99_project.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'core' / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'plit99_project.wsgi.application'

DATABASES = {
    'default': dj_database_url.config(
        default=f"sqlite:///{(DATA_DIR / 'db.sqlite3').as_posix()}",
    )
}

if DATABASES['default']['ENGINE'] == 'django.db.backends.sqlite3':
    database_name = DATABASES['default']['NAME']
    if database_name != ':memory:':
        reject_public_data_path(database_name)
        if Path(database_name).resolve().is_relative_to((DATA_DIR / 'media').resolve()):
            raise ImproperlyConfigured('SQLite database must stay outside the public media directory.')
    DATABASES['default']['CONN_MAX_AGE'] = 0
    DATABASES['default']['OPTIONS'] = {
        'timeout': 30,
    }
else:
    if DATABASES['default']['ENGINE'] != 'django.db.backends.postgresql':
        raise ImproperlyConfigured('Only SQLite and PostgreSQL are supported.')
    DATABASES['default']['CONN_MAX_AGE'] = 600
    DATABASES['default']['CONN_HEALTH_CHECKS'] = True
    DATABASES['default'].setdefault('OPTIONS', {}).update({
        'connect_timeout': 5,
        'options': '-c statement_timeout=15000 -c lock_timeout=5000',
    })
    if IS_PRODUCTION:
        ssl_mode = DATABASES['default']['OPTIONS'].setdefault('sslmode', 'verify-full')
        if ssl_mode != 'verify-full':
            raise ImproperlyConfigured('Production PostgreSQL requires sslmode=verify-full.')

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', 'OPTIONS': {'min_length': 12}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

LANGUAGE_CODE = 'ru-ru'
TIME_ZONE = 'Asia/Bishkek'
USE_I18N = True
USE_TZ = True

STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATIC_ROOT = BASE_DIR / 'staticfiles'
STORAGES = {
    'default': {
        'BACKEND': 'django.core.files.storage.FileSystemStorage',
    },
    'staticfiles': {
        'BACKEND': 'whitenoise.storage.CompressedManifestStaticFilesStorage' if IS_PRODUCTION else 'whitenoise.storage.CompressedStaticFilesStorage',
    },
}
WHITENOISE_MANIFEST_STRICT = env_bool('WHITENOISE_MANIFEST_STRICT', False)
WHITENOISE_USE_FINDERS = not IS_PRODUCTION
WHITENOISE_AUTOREFRESH = not IS_PRODUCTION

MEDIA_URL = '/media/'
MEDIA_ROOT = DATA_DIR / 'media'
MEDIA_ROOT.mkdir(parents=True, exist_ok=True)
SERVE_MEDIA_FILES = env_bool('SERVE_MEDIA_FILES', True)

CSRF_TRUSTED_ORIGINS = env_list('CSRF_TRUSTED_ORIGINS')

# Enable only behind a proxy that strips/replaces client-supplied headers.
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https') if env_bool('TRUST_PROXY_HEADERS') else None
USE_X_FORWARDED_HOST = False

SESSION_ENGINE = os.getenv('SESSION_ENGINE', 'django.contrib.sessions.backends.db')
MESSAGE_STORAGE = os.getenv(
    'MESSAGE_STORAGE',
    'django.contrib.messages.storage.fallback.FallbackStorage',
)

SESSION_COOKIE_SECURE = env_bool('SESSION_COOKIE_SECURE', IS_PRODUCTION)
CSRF_COOKIE_SECURE = env_bool('CSRF_COOKIE_SECURE', IS_PRODUCTION)
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_AGE = 60 * 60 * 8
SECURE_SSL_REDIRECT = env_bool('SECURE_SSL_REDIRECT', IS_PRODUCTION)
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = os.getenv('SECURE_REFERRER_POLICY', 'same-origin')
X_FRAME_OPTIONS = os.getenv('X_FRAME_OPTIONS', 'DENY')

SECURE_HSTS_SECONDS = env_int('SECURE_HSTS_SECONDS', 31536000 if IS_PRODUCTION else 0)
SECURE_HSTS_INCLUDE_SUBDOMAINS = env_bool('SECURE_HSTS_INCLUDE_SUBDOMAINS', False)
SECURE_HSTS_PRELOAD = env_bool('SECURE_HSTS_PRELOAD', False)

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

DATA_UPLOAD_MAX_MEMORY_SIZE = 1024 * 1024
DATA_UPLOAD_MAX_NUMBER_FIELDS = 200
DATA_UPLOAD_MAX_NUMBER_FILES = 10
FILE_UPLOAD_MAX_MEMORY_SIZE = 2 * 1024 * 1024
MAX_UPLOAD_IMAGE_BYTES = 10 * 1024 * 1024
MAX_UPLOAD_IMAGE_PIXELS = 20_000_000
FILE_UPLOAD_PERMISSIONS = 0o600
FILE_UPLOAD_DIRECTORY_PERMISSIONS = 0o700
ADMIN_LOGIN_WINDOW_SECONDS = 300
ADMIN_LOGIN_IP_LIMIT = 20
ADMIN_LOGIN_ACCOUNT_LIMIT = 10

if IS_PRODUCTION and not all((SESSION_COOKIE_SECURE, CSRF_COOKIE_SECURE, SECURE_SSL_REDIRECT)):
    raise ImproperlyConfigured('Production requires HTTPS and secure cookies.')
