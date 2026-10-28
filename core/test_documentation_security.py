"""Regression scenarios mapped to the pinned references in SECURITY_RESEARCH.md."""
import os
import secrets
import subprocess
import sys
import tempfile
import shutil
import zipfile
from html import escape
from html.parser import HTMLParser
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, SimpleTestCase, TestCase, override_settings
from PIL import Image

from .content_security import sanitize_rich_text, video_embed_url
from .models import News, NewsCategory
from .templatetags.content_format import render_rich_text
from .tests import build_test_image, make_workspace_media_root


@override_settings(DEBUG=False, SECURE_SSL_REDIRECT=False)
class UnicodeLoginLimitTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = get_user_model().objects.create_superuser('securityadmin', password='Test-only-A7#example')

    def test_fullwidth_username_uses_normal_django_login(self):
        fullwidth = ''.join(chr(ord(char) + 0xFEE0) for char in 'securityadmin')
        response = self.client.post('/admin/login/', {'username': fullwidth, 'password': 'Test-only-A7#example'})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.session['_auth_user_id'], str(self.user.pk))

    @override_settings(ADMIN_LOGIN_ACCOUNT_LIMIT=1, ADMIN_LOGIN_IP_LIMIT=100)
    @patch('core.middleware.time.time', return_value=1_800_000_000)
    def test_unicode_normalization_cannot_bypass_account_limit(self, clock):
        response = Client().post('/admin/login/', {'username': 'securityadmin', 'password': 'wrong'}, REMOTE_ADDR='192.0.2.1')
        self.assertEqual(response.status_code, 200)
        fullwidth = ''.join(chr(ord(char) + 0xFEE0) for char in 'securityadmin')
        response = Client().post('/admin/login/', {'username': fullwidth, 'password': 'wrong'}, REMOTE_ADDR='192.0.2.2')
        self.assertEqual(response.status_code, 429)


class ProductionConfigurationTests(SimpleTestCase):
    def load_configuration(self, changes):
        with tempfile.TemporaryDirectory(prefix='plit99-settings-test-') as directory:
            # Do not inherit real DB credentials or secrets into the subprocess.
            environment = {key: os.environ[key] for key in ('SystemRoot', 'WINDIR', 'PATH', 'TEMP', 'TMP') if key in os.environ}
            environment.update({
                'APP_ENV': 'production', 'DEBUG': 'False',
                'SECRET_KEY': secrets.token_urlsafe(64),
                'APP_DATA_DIR': directory,
                'DATABASE_URL': f'sqlite:///{Path(directory).as_posix()}/test.sqlite3',
                'ALLOWED_HOSTS': 'example.com',
            })
            environment.update({key: value.replace('{data_dir}', Path(directory).as_posix()) for key, value in changes.items()})
            return subprocess.run(
                [sys.executable, '-c', 'import plit99_project.settings'],
                cwd=settings.BASE_DIR, env=environment, capture_output=True, text=True, timeout=15,
            )

    def test_production_rejects_debug_and_insecure_cookies(self):
        for changes in ({'DEBUG': 'True'}, {'SESSION_COOKIE_SECURE': 'False'}, {'CSRF_COOKIE_SECURE': 'False'}, {'SECURE_SSL_REDIRECT': 'False'}, {'ALLOWED_HOSTS': '*'}, {'SECRET_KEY': 'invalid'}):
            with self.subTest(changes=tuple(changes)):
                result = self.load_configuration(changes)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('ImproperlyConfigured', result.stderr)

    def test_valid_production_configuration_loads(self):
        self.assertEqual(self.load_configuration({}).returncode, 0)

    def test_runtime_data_cannot_be_placed_under_public_static(self):
        for directory in ('static', 'staticfiles'):
            with self.subTest(directory=directory):
                result = self.load_configuration({'APP_DATA_DIR': str(settings.BASE_DIR / directory)})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('ImproperlyConfigured', result.stderr)

    def test_sqlite_database_cannot_be_placed_under_public_static(self):
        for directory in ('static', 'staticfiles'):
            with self.subTest(directory=directory):
                path = (settings.BASE_DIR / directory / 'configuration-test.sqlite3').as_posix()
                result = self.load_configuration({'DATABASE_URL': f'sqlite:///{path}'})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('ImproperlyConfigured', result.stderr)

    def test_production_cannot_downgrade_postgres_certificate_validation(self):
        for mode in ('disable', 'allow', 'prefer', 'require', 'verify-ca'):
            with self.subTest(mode=mode):
                result = self.load_configuration({'DATABASE_URL': f'postgresql://test_role@db.example/test_db?sslmode={mode}'})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('ImproperlyConfigured', result.stderr)

    def test_postgres_verify_full_loads_without_connecting(self):
        result = self.load_configuration({'DATABASE_URL': 'postgresql://test_role@db.example/test_db?sslmode=verify-full'})
        self.assertEqual(result.returncode, 0)

    def test_sqlite_database_cannot_be_placed_under_public_media(self):
        result = self.load_configuration({'DATABASE_URL': 'sqlite:///{data_dir}/media/test.sqlite3'})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('ImproperlyConfigured', result.stderr)


@override_settings(DEBUG=False, SECURE_SSL_REDIRECT=False)
class RequestBoundaryTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.admin = get_user_model().objects.create_superuser('boundaryadmin', password='Test-only-A7#example')
        cls.news = News.objects.create(title='Boundary public', slug='boundary-public', excerpt='Public', content='Original content')
        cls.draft = News.objects.create(title='DRAFT_PRIVATE_SENTINEL', slug='boundary-draft', excerpt='Private', content='DRAFT_PRIVATE_SENTINEL', is_published=False)
        NewsCategory.objects.create(name='Boundary category', slug='boundary-category')

    def test_arbitrary_orm_lookups_cannot_expose_drafts(self):
        payload = {'is_published': 'false', 'is_published__in': 'false,true', 'content__regex': '.*', 'password__startswith': 'p', 'category__news__is_published': 'false', 'filter[is_published]': 'false'}
        for path in ('/news/', '/news-gallery/'):
            response = self.client.get(path, payload)
            self.assertEqual(response.status_code, 200)
            self.assertContains(response, 'Boundary public')
            self.assertNotContains(response, 'DRAFT_PRIVATE_SENTINEL')

    def test_duplicate_category_parameters_do_not_change_query_structure(self):
        for query in ('cat=boundary-category&cat=%27%20OR%201%3D1--', 'cat=boundary-category&cat[]=x', 'cat[slug]=boundary-category'):
            response = self.client.get('/news/?' + query)
            self.assertIn(response.status_code, (200, 404))
            self.assertNotContains(response, 'DRAFT_PRIVATE_SENTINEL', status_code=response.status_code)
        self.assertEqual(News.objects.count(), 2)

    @override_settings(ADMIN_LOGIN_ACCOUNT_LIMIT=1, ADMIN_LOGIN_IP_LIMIT=100)
    @patch('core.middleware.time.time', return_value=1_800_000_000)
    def test_duplicate_username_uses_same_value_for_limiter_and_login(self, clock):
        first = self.client.post('/admin/login/', {'username': 'boundaryadmin', 'password': 'wrong'}, REMOTE_ADDR='192.0.2.1')
        self.assertEqual(first.status_code, 200)
        response = self.client.post('/admin/login/', 'username=decoy&username=boundaryadmin&password=wrong', content_type='application/x-www-form-urlencoded', REMOTE_ADDR='192.0.2.2')
        self.assertEqual(response.status_code, 429)

    def test_login_rotates_anonymous_session_identifier(self):
        session = self.client.session
        session['test-only'] = 'anonymous-session-marker'
        session.save()
        old_key = session.session_key
        response = self.client.post('/admin/login/', {'username': 'boundaryadmin', 'password': 'Test-only-A7#example'})
        self.assertEqual(response.status_code, 302)
        self.assertNotEqual(self.client.session.session_key, old_key)
        stale = Client()
        stale.cookies[settings.SESSION_COOKIE_NAME] = old_key
        self.assertTrue(stale.get('/admin/')['Location'].startswith('/admin/login/'))

    def test_logout_invalidates_previous_session(self):
        self.client.force_login(self.admin)
        old_key = self.client.session.session_key
        response = self.client.post('/admin/logout/')
        self.assertEqual(response.status_code, 200)
        stale = Client()
        stale.cookies[settings.SESSION_COOKIE_NAME] = old_key
        self.assertTrue(stale.get('/admin/')['Location'].startswith('/admin/login/'))

    def test_password_change_invalidates_other_sessions(self):
        self.client.force_login(self.admin)
        self.admin.set_password('Another-test-only-A7#example')
        self.admin.save(update_fields=['password'])
        self.assertTrue(self.client.get('/admin/')['Location'].startswith('/admin/login/'))

    def test_staff_revocation_takes_effect_for_existing_session(self):
        self.client.force_login(self.admin)
        self.admin.is_staff = False
        self.admin.save(update_fields=['is_staff'])
        self.assertTrue(self.client.get('/admin/')['Location'].startswith('/admin/login/'))

    def test_open_redirect_and_crlf_candidates_are_rejected_after_login(self):
        candidates = ('//attacker.invalid/', '////attacker.invalid/', '/\\attacker.invalid/', 'https://testserver@attacker.invalid/', 'javascript:alert(1)', '\r\nX-Security-Injected: yes', 'https://attacker.invalid/%0d%0aX-Security-Injected:yes')
        for candidate in candidates:
            with self.subTest(candidate=candidate):
                client = Client()
                client.force_login(self.admin)
                # An already authenticated admin follows the same validated next
                # decision without spending time hashing a password per payload.
                response = client.get('/admin/login/', {'next': candidate})
                self.assertEqual(response.status_code, 302)
                self.assertEqual(response['Location'], '/admin/')
                self.assertNotIn('X-Security-Injected', response)

    def test_host_and_rewrite_headers_do_not_grant_admin_access(self):
        response = self.client.get('/healthz/', HTTP_X_ORIGINAL_URL='/admin/auth/user/', HTTP_X_REWRITE_URL='/admin/auth/user/', HTTP_X_REAL_IP='127.0.0.1', HTTP_FORWARDED='for=127.0.0.1;host=attacker.invalid;proto=https')
        self.assertEqual(response.json(), {'status': 'ok'})
        self.assertTrue(self.client.get('/admin/', HTTP_X_ORIGINAL_URL='/')['Location'].startswith('/admin/login/'))

    def test_cross_origin_and_null_origins_are_not_reflected(self):
        self.client.force_login(self.admin)
        for origin in ('https://attacker.invalid', 'null', 'https://testserver.attacker.invalid'):
            for path in ('/healthz/', '/admin/auth/user/'):
                response = self.client.get(path, HTTP_ORIGIN=origin)
                self.assertEqual(response.status_code, 200)
                self.assertNotIn('Access-Control-Allow-Origin', response)
                self.assertNotIn('Access-Control-Allow-Credentials', response)

    def test_csrf_simple_content_types_and_invalid_tokens_cannot_write(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.admin)
        for content_type in ('text/plain', 'application/json', 'application/x-www-form-urlencoded'):
            response = client.post('/admin/core/news/add/', '{"title":"CSRF injection"}', content_type=content_type, HTTP_ORIGIN='https://attacker.invalid')
            self.assertEqual(response.status_code, 403)
        client.get('/admin/login/')
        response = client.post('/admin/core/news/add/', {'title': 'CSRF injection', 'csrfmiddlewaretoken': 'A' * 64})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(News.objects.count(), 2)

    def test_secure_csrf_rejects_missing_or_untrusted_referer(self):
        client = Client(enforce_csrf_checks=True)
        client.get('/admin/login/', secure=True)
        token = client.cookies['csrftoken'].value
        for referer in (None, 'https://testserver.attacker.invalid/', 'http://testserver/'):
            headers = {} if referer is None else {'HTTP_REFERER': referer}
            response = client.post('/admin/login/', {'username': 'boundaryadmin', 'password': 'wrong', 'csrfmiddlewaretoken': token}, secure=True, **headers)
            self.assertEqual(response.status_code, 403)

    def test_css_suffix_does_not_expose_authenticated_admin_response(self):
        self.client.force_login(self.admin)
        for path in ('/admin/auth/user/private.css', '/admin/auth/user/;.css', '/admin/auth/user/..%2fprivate.js'):
            response = self.client.get(path)
            # CommonMiddleware may append a slash with a 301. A redirect does
            # not serve the authenticated page under the deceptive CSS URL.
            self.assertIn(response.status_code, (301, 302, 404))
            if response.status_code in (301, 302):
                self.assertTrue(response['Location'].startswith('/admin/'))
            self.assertNotIn('Boundary public', response.content.decode())
            anonymous = Client().get(path)
            self.assertNotEqual(anonymous.status_code, 200)

    def test_template_payloads_are_data_and_cannot_read_secrets(self):
        payload = "SSTI_MARKER_{{364|add:733}} {% debug %} {{ messages.storages.0.signer.key }} {% include 'admin/base.html' %}"
        News.objects.filter(pk=self.news.pk).update(content=payload)
        response = self.client.get(self.news.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '{{364|add:733}}')
        self.assertNotContains(response, 'SSTI_MARKER_1097')
        self.assertNotContains(response, settings.SECRET_KEY)


class SanitizerBoundaryTests(SimpleTestCase):
    def test_mutated_xss_protocol_obfuscation_and_dom_clobbering(self):
        class AuditParser(HTMLParser):
            def handle_starttag(self, tag, attrs):
                if tag in {'script', 'svg', 'math', 'iframe', 'object', 'form', 'input', 'base', 'style'}:
                    raise AssertionError(f'Dangerous element survived: {tag}')
                for key, value in attrs:
                    if key.startswith('on') or key in {'style', 'id', 'name', 'srcdoc'}:
                        raise AssertionError(f'Dangerous attribute survived: {key}')
                    if key == 'href' and value and any(scheme in value.lower() for scheme in ('javascript:', 'data:', 'vbscript:')):
                        raise AssertionError('Dangerous URL survived')

        vectors = (
            '<math><mtext><table><mglyph><style><!--</style><img title="--><img src=1 onerror=alert(1)>">',
            '<svg><style><a id="</style><img src=1 onerror=alert(1)>">',
            '<a href="jav&#x09;ascript:alert(1)">link</a>',
            '<a href="data:text/html;base64,PHNjcmlwdD4=">link</a>',
            '<form id=main-nav><input name=action></form><a id=location name=href href=https://attacker.invalid/>',
            '<p style="background:image-set(attr(value))">text</p><style>@import "https://attacker.invalid";</style>',
            '<base href="https://attacker.invalid"><iframe srcdoc="<script>alert(1)</script>"></iframe>',
        )
        for vector in vectors:
            with self.subTest(vector=vector):
                clean = str(render_rich_text(vector))
                AuditParser().feed(clean)
                self.assertEqual(sanitize_rich_text(sanitize_rich_text(vector)), sanitize_rich_text(vector))

    def test_deeply_encoded_html_does_not_reactivate_script(self):
        value = '<script>alert(1)</script>'
        for _ in range(12):
            value = escape(value)
        result = str(render_rich_text(value))
        self.assertNotIn('<script', result.lower())

    def test_video_schemes_loopback_and_deceptive_hosts_are_rejected(self):
        for value in ('file:///etc/passwd', 'gopher://127.0.0.1:6379/', 'https://2130706433/', 'https://[::1]/', 'https://169.254.169.254/latest/meta-data/', 'https://www.youtube.com.attacker.invalid/embed/abcdefghijk', 'https://www.youtube.com@attacker.invalid/embed/abcdefghijk', 'https://www.youtube.com\\@attacker.invalid/embed/abcdefghijk'):
            self.assertEqual(video_embed_url(value), '')


@override_settings(SECURE_SSL_REDIRECT=False)
class UploadBoundaryTests(TestCase):
    def setUp(self):
        self.media_root = make_workspace_media_root()
        self.override = self.settings(MEDIA_ROOT=self.media_root)
        self.override.enable()
        self.addCleanup(self.override.disable)
        self.addCleanup(shutil.rmtree, self.media_root, True)

    def save_news(self, name, data):
        return News.objects.create(title='Upload boundary', excerpt='Summary', content='Text', cover_image=SimpleUploadedFile(name, data, content_type='image/jpeg'))

    def test_configuration_and_double_extension_names_become_random_image_names(self):
        for index, name in enumerate(('web.config', '__init__.py', 'shell.php.jpg', 'file.asp::$data.jpg', 'name.jpg.php', '..\\payload.png')):
            with self.subTest(name=name):
                news = News(title=f'Upload {index}', excerpt='Summary', content='Text', cover_image=SimpleUploadedFile(name, build_test_image(30, 30)))
                news.save()
                self.assertRegex(news.cover_image.name, r'^news/covers/[0-9a-f]{32}\.jpg$')
                with Image.open(news.cover_image.path) as image:
                    self.assertEqual(image.format, 'JPEG')

    def test_appended_payload_is_removed_by_reencoding(self):
        marker = b'APPENDED_SECURITY_TEST_MARKER'
        news = self.save_news('image.jpg', build_test_image(30, 30) + marker)
        self.assertNotIn(marker, Path(news.cover_image.path).read_bytes())

    def test_exif_metadata_is_not_published(self):
        image = Image.new('RGB', (30, 30))
        exif = Image.Exif()
        exif[315] = 'EXIF_SECURITY_TEST_MARKER'
        buffer = BytesIO()
        image.save(buffer, format='JPEG', exif=exif)
        news = self.save_news('metadata.jpg', buffer.getvalue())
        with Image.open(news.cover_image.path) as saved:
            self.assertEqual(len(saved.getexif()), 0)
        self.assertNotIn(b'EXIF_SECURITY_TEST_MARKER', Path(news.cover_image.path).read_bytes())

    def test_gif_svg_and_zip_are_rejected_without_archive_extraction(self):
        gif = BytesIO()
        Image.new('RGB', (10, 10)).save(gif, format='GIF')
        archive = BytesIO()
        with zipfile.ZipFile(archive, 'w') as zipped:
            zipped.writestr('../test-only-marker.txt', 'not extracted')
        for data in (gif.getvalue(), b'<svg onload="alert(1)"/>', archive.getvalue()):
            with self.assertRaises(ValidationError):
                self.save_news('disguised.jpg', data)
        self.assertEqual(News.objects.count(), 0)
        self.assertEqual(list(self.media_root.rglob('*')), [])

    def test_processing_error_does_not_store_original_upload(self):
        with patch('core.media_utils.ImageOps.exif_transpose', side_effect=OSError('synthetic decode failure')):
            with self.assertRaises(ValidationError):
                self.save_news('image.jpg', build_test_image(30, 30))
        self.assertFalse(News.objects.exists())
        self.assertEqual(list(self.media_root.rglob('*')), [])
