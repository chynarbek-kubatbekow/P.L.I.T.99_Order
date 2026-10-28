import os
import shutil
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import DatabaseError, close_old_connections
from django.test import Client, RequestFactory, SimpleTestCase, TestCase, TransactionTestCase, override_settings
from django.utils import timezone

from .content_security import sanitize_rich_text, video_embed_url
from .middleware import AdminLoginThrottleMiddleware
from .media_utils import resolve_media_file_path
from .models import AdminLoginThrottle, GalleryItem, News, NewsCategory
from .tests import build_test_image, make_workspace_media_root


@override_settings(DEBUG=False, SECURE_SSL_REDIRECT=False)
class PublicSecurityTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.news = News.objects.create(title='Visible news', slug='visible', excerpt='Summary', content='<p>Body</p>')
        cls.draft = News.objects.create(title='Private draft marker', slug='private-draft', excerpt='Private', content='Secret draft', is_published=False)
        NewsCategory.objects.create(name='Category', slug='category')

    def test_unknown_url_does_not_reveal_routes_or_settings(self):
        response = self.client.get('/ddd//')
        self.assertEqual(response.status_code, 404)
        for marker in ('URLconf', 'urlpatterns', 'plit99_project', 'DEBUG', 'Request Method', 'admin/'):
            self.assertNotContains(response, marker, status_code=404)

    def test_server_exception_does_not_reveal_traceback_or_exception(self):
        client = Client(raise_request_exception=False)
        with patch('core.views.render', side_effect=RuntimeError('sensitive-test-marker')):
            response = client.get('/about/')
        self.assertEqual(response.status_code, 500)
        for marker in ('sensitive-test-marker', 'Traceback', 'settings.py'):
            self.assertNotContains(response, marker, status_code=500)

    def test_host_header_is_validated(self):
        self.assertEqual(self.client.get('/healthz/', HTTP_HOST='attacker.invalid').status_code, 400)

    def test_forwarded_host_is_ignored(self):
        response = self.client.get('/healthz/', HTTP_X_FORWARDED_HOST='attacker.invalid')
        self.assertEqual(response.status_code, 200)

    @override_settings(SECURE_SSL_REDIRECT=True, SECURE_PROXY_SSL_HEADER=None)
    def test_forged_forwarded_proto_cannot_bypass_https_redirect(self):
        response = self.client.get('/healthz/', HTTP_X_FORWARDED_PROTO='https')
        self.assertEqual(response.status_code, 301)
        self.assertTrue(response['Location'].startswith('https://'))

    def test_public_pages_keep_working(self):
        for url in ('/', '/about/', '/education/', '/results/', '/admission/', '/news-gallery/', '/news/', '/news/visible/', '/gallery/', '/contacts/', '/healthz/'):
            with self.subTest(url=url):
                self.assertEqual(self.client.get(url).status_code, 200)

    def test_public_views_reject_writes(self):
        for method in ('post', 'put', 'patch', 'delete'):
            for url in ('/', '/news/', '/news/visible/', '/gallery/', '/news-gallery/', '/healthz/'):
                with self.subTest(method=method, url=url):
                    self.assertEqual(getattr(self.client, method)(url, {'is_published': True}).status_code, 405)
        self.assertEqual(News.objects.count(), 2)

    def test_unpublished_news_is_not_accessible(self):
        self.assertEqual(self.client.get('/news/private-draft/').status_code, 404)
        for url in ('/', '/news/', '/news-gallery/'):
            self.assertNotContains(self.client.get(url), 'Private draft marker')

    def test_sql_injection_does_not_bypass_filters_or_change_database(self):
        for payload in ("' OR 1=1--", "category'; DROP TABLE core_news;--", '${7*7}', '{{7*7}}'):
            with self.subTest(payload=payload):
                self.assertEqual(self.client.get('/news/', {'cat': payload}).status_code, 404)
                self.assertEqual(self.client.get('/gallery/', {'cat': payload}).status_code, 404)
        self.assertEqual(News.objects.count(), 2)
        self.assertEqual(NewsCategory.objects.count(), 1)

    def test_existing_database_html_is_sanitized_at_render_time(self):
        payload = '<p>Allowed text</p><script>window.XSS_MARKER=1</script><img src=x onerror="alert(1)"><a href="javascript:alert(1)">link</a>'
        # Bypass model.save to represent legacy or imported rows.
        News.objects.filter(pk=self.news.pk).update(content=payload)
        response = self.client.get('/news/visible/')
        self.assertContains(response, '<p>Allowed text</p>')
        for marker in ('window.XSS_MARKER', 'onerror=', 'javascript:'):
            self.assertNotContains(response, marker)

    def test_news_title_and_excerpt_are_escaped(self):
        News.objects.filter(pk=self.news.pk).update(title='<img src=x onerror=alert(1)>', excerpt='<script>alert(2)</script>')
        response = self.client.get('/news/')
        self.assertNotContains(response, '<img src=x onerror=alert(1)>')
        self.assertNotContains(response, '<script>alert(2)</script>')

    def test_legacy_css_injection_is_not_rendered(self):
        News.objects.filter(pk=self.news.pk).update(cover_gradient='url(https://attacker.invalid/track)')
        self.assertNotContains(self.client.get('/news/visible/'), 'attacker.invalid')

    def test_browser_security_headers(self):
        response = self.client.get('/')
        self.assertEqual(response['X-Frame-Options'], 'DENY')
        self.assertEqual(response['X-Content-Type-Options'], 'nosniff')
        self.assertIn("object-src 'none'", response['Content-Security-Policy'])
        self.assertIn("frame-ancestors 'none'", response['Content-Security-Policy'])
        script_policy = response['Content-Security-Policy'].split('script-src ')[1].split(';')[0]
        self.assertNotIn('unsafe-inline', script_policy)
        self.assertIn('camera=()', response['Permissions-Policy'])

    def test_private_project_files_are_not_exposed(self):
        for path in ('/.env', '/db.sqlite3', '/.git/config', '/plit99_project/settings.py', '/.runtime-data/.secret-key'):
            self.assertEqual(self.client.get(path).status_code, 404)


class ContentValidationTests(SimpleTestCase):
    def test_xss_payloads_including_entity_and_namespace_bypasses(self):
        payloads = (
            '<script>alert(1)</script>',
            '&amp;lt;img src=x onerror=alert(1)&amp;gt;',
            '<svg><a xlink:href="javascript:alert(1)">x</a></svg>',
            '<math><mtext><img src=x onerror=alert(1)></mtext></math>',
            '<a href="jav&#x61;script:alert(1)">x</a>',
            '<a href="data:text/html,evil">x</a>',
            '<iframe srcdoc="<script>alert(1)</script>"></iframe>',
            '<p style="background:url(https://attacker.invalid)">x</p>',
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                clean = sanitize_rich_text(payload)
                for marker in ('<script', 'onerror', '<svg', '<math', 'javascript:', 'data:', 'srcdoc', 'style='):
                    self.assertNotIn(marker, clean)

    def test_formatting_and_safe_links_are_preserved(self):
        clean = sanitize_rich_text('<h2>Title</h2><p><strong>Text</strong> <a href="https://example.com/">link</a></p>')
        self.assertIn('<h2>Title</h2>', clean)
        self.assertIn('<strong>Text</strong>', clean)
        self.assertIn('href="https://example.com/"', clean)
        self.assertIn('noopener', clean)

    def test_video_urls_require_exact_trusted_host_and_safe_path(self):
        for url in ('javascript:alert(1)', 'https://youtube.com.attacker.invalid/embed/abcdefghijk', 'https://user:pass@youtube.com/embed/abcdefghijk', 'http://youtube.com/embed/abcdefghijk', 'https://127.0.0.1/', 'https://youtube.com:444/embed/abcdefghijk', 'https://www.youtube.com/redirect?q=evil'):
            self.assertEqual(video_embed_url(url), '')
        self.assertEqual(video_embed_url('https://youtu.be/abcdefghijk'), 'https://www.youtube-nocookie.com/embed/abcdefghijk')
        self.assertEqual(video_embed_url('https://www.youtube.com/watch?v=abcdefghijk'), 'https://www.youtube-nocookie.com/embed/abcdefghijk')
        self.assertEqual(video_embed_url('https://vimeo.com/1234567'), 'https://player.vimeo.com/video/1234567')


@override_settings(SECURE_SSL_REDIRECT=False)
class UploadSecurityTests(TestCase):
    def setUp(self):
        self.media_root = make_workspace_media_root()
        self.override = self.settings(MEDIA_ROOT=self.media_root)
        self.override.enable()
        self.addCleanup(self.override.disable)
        self.addCleanup(shutil.rmtree, self.media_root, True)

    def test_fake_image_is_rejected_without_persisting_file_or_news(self):
        with self.assertRaises(ValidationError):
            News.objects.create(title='Fake', excerpt='Fake', content='Fake', cover_image=SimpleUploadedFile('evil.jpg', b'<script>alert(1)</script>', content_type='image/jpeg'))
        self.assertFalse(News.objects.exists())
        self.assertEqual(list(self.media_root.rglob('*')), [])

    @override_settings(MAX_UPLOAD_IMAGE_BYTES=10)
    def test_upload_byte_limit(self):
        with self.assertRaises(ValidationError):
            News.objects.create(title='Big', excerpt='x', content='x', cover_image=SimpleUploadedFile('big.jpg', build_test_image(30, 30)))

    @override_settings(MAX_UPLOAD_IMAGE_PIXELS=100)
    def test_decompression_pixel_limit(self):
        with self.assertRaises(ValidationError):
            News.objects.create(title='Big', excerpt='x', content='x', cover_image=SimpleUploadedFile('big.jpg', build_test_image(30, 30)))

    def test_media_does_not_serve_active_or_private_files(self):
        for name, data in [('evil.html', b'<script>alert(1)</script>'), ('evil.svg', b'<svg onload="alert(1)"/>'), ('database.sqlite3', b'private'), ('fake.jpg', b'<script>alert(1)</script>'), ('.secret.png', build_test_image(10, 10))]:
            (self.media_root / name).write_bytes(data)
            self.assertEqual(self.client.get('/media/' + name).status_code, 404)

    def test_media_path_traversal_is_rejected(self):
        for path in ('../manage.py', '..\\manage.py', '../.env', 'news/../../.env', '%2e%2e/%2eenv'):
            self.assertIsNone(resolve_media_file_path(path))
            self.assertEqual(self.client.get('/media/' + path).status_code, 404)

    def test_symlink_cannot_escape_media_root(self):
        link = self.media_root / 'outside'
        try:
            link.symlink_to(settings.BASE_DIR, target_is_directory=True)
        except OSError:
            self.skipTest('Creating symlinks requires Windows Developer Mode or privilege.')
        self.assertIsNone(resolve_media_file_path('outside/manage.py'))

    def test_model_rejects_css_and_video_injection(self):
        with self.assertRaises(ValidationError):
            News.objects.create(title='CSS', excerpt='x', content='x', cover_gradient='red;position:fixed;inset:0')
        with self.assertRaises(ValidationError):
            GalleryItem.objects.create(media_type='video', video_url='https://attacker.invalid/')


@override_settings(SECURE_SSL_REDIRECT=False, DEBUG=False)
class AdminSecurityTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.staff = User.objects.create_user('staff', password='Test-only-A7#example', is_staff=True)
        cls.admin = User.objects.create_superuser('test-admin', password='Test-only-A7#example')
        cls.reader = User.objects.create_user('reader', password='Test-only-A7#example')

    def test_anonymous_and_non_staff_cannot_write_news(self):
        response = self.client.post('/admin/core/news/add/', {'title': 'Injected'})
        self.assertEqual(response.status_code, 302)
        self.assertIn('/admin/login/', response['Location'])
        self.client.force_login(self.staff)
        self.assertEqual(self.client.post('/admin/core/news/add/', {'title': 'Injected'}).status_code, 403)
        self.client.force_login(self.reader)
        response = self.client.post('/admin/core/news/add/', {'title': 'Injected'})
        self.assertEqual(response.status_code, 302)
        self.assertIn('/admin/login/', response['Location'])
        self.assertFalse(News.objects.exists())

    def test_authenticated_admin_still_needs_csrf_token(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.admin)
        response = client.post('/admin/core/news/add/', {'title': 'Injected'})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(News.objects.exists())

    def test_login_csrf_and_forged_origin_are_rejected(self):
        client = Client(enforce_csrf_checks=True)
        client.get('/admin/login/')
        self.assertEqual(client.post('/admin/login/', {'username': 'test-admin', 'password': 'wrong'}).status_code, 403)
        token = client.cookies['csrftoken'].value
        response = client.post('/admin/login/', {'username': 'test-admin', 'password': 'wrong', 'csrfmiddlewaretoken': token}, HTTP_ORIGIN='https://attacker.invalid')
        self.assertEqual(response.status_code, 403)
        self.assertFalse(AdminLoginThrottle.objects.exists())

    @override_settings(ADMIN_LOGIN_ACCOUNT_LIMIT=2, ADMIN_LOGIN_IP_LIMIT=100)
    def test_brute_force_account_limit_survives_new_clients_and_addresses(self):
        for address in ('192.0.2.1', '192.0.2.2'):
            self.assertEqual(Client().post('/admin/login/', {'username': 'test-admin', 'password': 'wrong'}, REMOTE_ADDR=address).status_code, 200)
        response = Client().post('/admin/login/', {'username': 'TEST-ADMIN', 'password': 'wrong'}, REMOTE_ADDR='192.0.2.3')
        self.assertEqual(response.status_code, 429)
        self.assertIn('Retry-After', response)

    @override_settings(ADMIN_LOGIN_IP_LIMIT=2, ADMIN_LOGIN_ACCOUNT_LIMIT=100)
    def test_forged_forwarded_for_does_not_bypass_ip_limit(self):
        for index in range(2):
            self.assertEqual(self.client.post('/admin/login/', {'username': f'user{index}', 'password': 'wrong'}, HTTP_X_FORWARDED_FOR=f'192.0.2.{index}').status_code, 200)
        response = self.client.post('/admin/login/', {'username': 'other', 'password': 'wrong'}, HTTP_X_FORWARDED_FOR='203.0.113.99')
        self.assertEqual(response.status_code, 429)

    def test_limiter_database_failure_denies_login(self):
        with patch('core.middleware.AdminLoginThrottle.objects.get_or_create', side_effect=DatabaseError):
            self.assertEqual(self.client.post('/admin/login/', {'username': 'x', 'password': 'x'}).status_code, 503)

    def test_oversized_body_and_excessive_fields_are_rejected(self):
        response = self.client.post('/admin/login/', {'username': 'x' * (settings.DATA_UPLOAD_MAX_MEMORY_SIZE + 1)})
        self.assertEqual(response.status_code, 400)
        response = self.client.post('/admin/login/', {f'field{i}': 'x' for i in range(settings.DATA_UPLOAD_MAX_NUMBER_FIELDS + 1)})
        self.assertEqual(response.status_code, 400)

    def test_normal_admin_login_and_no_open_redirect(self):
        response = self.client.post('/admin/login/?next=https://attacker.invalid/', {'username': 'test-admin', 'password': 'Test-only-A7#example'})
        self.assertEqual(response.status_code, 302)
        self.assertNotIn('attacker.invalid', response['Location'])
        self.assertEqual(self.client.get('/admin/core/news/add/').status_code, 200)

    def test_admin_can_save_news_without_changing_the_publication_workflow(self):
        self.client.force_login(self.admin)
        response = self.client.post('/admin/core/news/add/', {
            'title': 'Published through admin', 'slug': '', 'excerpt': 'Summary',
            'content': '<p>Formatted text</p><script>alert(1)</script>',
            'cover_emoji': 'N', 'cover_gradient': 'linear-gradient(135deg,#0D3060,#1668C0)',
            'is_published': 'on', 'published_at_0': '2026-10-28', 'published_at_1': '12:00:00',
            '_save': 'Save',
        })
        self.assertEqual(response.status_code, 302)
        news = News.objects.get(title='Published through admin')
        self.assertTrue(news.is_published)
        self.assertEqual(news.content, '<p>Formatted text</p>')
        self.assertEqual(self.client.get(news.get_absolute_url()).status_code, 200)

    @override_settings(SESSION_COOKIE_SECURE=True, CSRF_COOKIE_SECURE=True)
    def test_session_cookie_security_flags(self):
        response = self.client.post('/admin/login/', {'username': 'test-admin', 'password': 'Test-only-A7#example'}, secure=True)
        self.assertEqual(response.status_code, 302)
        cookie = response.cookies[settings.SESSION_COOKIE_NAME]
        self.assertTrue(cookie['secure'])
        self.assertTrue(cookie['httponly'])
        self.assertEqual(cookie['samesite'], 'Lax')

    def test_weak_bootstrap_password_is_rejected(self):
        with patch.dict(os.environ, {'DJANGO_SUPERUSER_USERNAME': 'bootstrap-test', 'DJANGO_SUPERUSER_PASSWORD': 'password'}):
            with self.assertRaises(CommandError):
                call_command('create_admin_if_missing')
        self.assertFalse(get_user_model().objects.filter(username='bootstrap-test').exists())

    def test_expired_buckets_can_be_cleaned_without_resetting_live_limits(self):
        AdminLoginThrottle.objects.create(key='expired', expires_at=timezone.now() - timedelta(seconds=1))
        AdminLoginThrottle.objects.create(key='live', expires_at=timezone.now() + timedelta(minutes=5))
        call_command('clear_login_throttles')
        self.assertEqual(list(AdminLoginThrottle.objects.values_list('key', flat=True)), ['live'])


@override_settings(ADMIN_LOGIN_IP_LIMIT=3, ADMIN_LOGIN_ACCOUNT_LIMIT=100)
class ConcurrentLoginLimitTests(TransactionTestCase):
    def test_concurrent_requests_cannot_exceed_ip_budget(self):
        def attempt(index):
            close_old_connections()
            try:
                request = RequestFactory().post('/admin/login/', {'username': f'parallel{index}', 'password': 'invalid'})
                request.resolver_match = SimpleNamespace(view_name='admin:login')
                response = AdminLoginThrottleMiddleware(lambda request: None).process_view(request, None, (), {})
                return 200 if response is None else response.status_code
            finally:
                close_old_connections()
        with ThreadPoolExecutor(max_workers=6) as executor:
            outcomes = list(executor.map(attempt, range(12)))
        self.assertGreater(outcomes.count(200), 0)
        self.assertLessEqual(outcomes.count(200), 3)
        self.assertTrue(all(code in {200, 429, 503} for code in outcomes))
