"""Negative authorization checks. All identities and records are test-only."""
import json
from importlib import import_module

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import Client, TestCase, override_settings

from .models import News


@override_settings(DEBUG=False, SECURE_SSL_REDIRECT=False)
class BackendAccessTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.reader = User.objects.create_user('access-reader', password='Test-only-A7#example')
        cls.viewer = User.objects.create_user('access-viewer', password='Test-only-A7#example', is_staff=True)
        cls.viewer.user_permissions.add(Permission.objects.get(codename='view_news', content_type__app_label='core'))
        cls.admin = User.objects.create_superuser('access-admin', password='Test-only-A7#example')
        cls.inactive = User.objects.create_superuser('access-inactive', password='Test-only-A7#example', is_active=False)
        cls.news = News.objects.create(title='Authorization test', slug='authorization-test', excerpt='Public summary', content='Original text')

    def assert_login_required(self, response):
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response['Location'].startswith('/admin/login/'))

    def test_anonymous_cannot_read_administrative_data(self):
        for path in ('/admin/', '/admin/auth/user/', '/admin/auth/group/', '/admin/core/news/', '/admin/core/galleryitem/', f'/admin/core/news/{self.news.pk}/change/', f'/admin/core/news/{self.news.pk}/history/', f'/admin/core/news/{self.news.pk}/delete/'):
            with self.subTest(path=path):
                self.assert_login_required(self.client.get(path))

    def test_anonymous_cannot_modify_or_delete_existing_objects(self):
        for path, payload in (
            (f'/admin/core/news/{self.news.pk}/change/', {'title': 'Unauthorized replacement'}),
            (f'/admin/core/news/{self.news.pk}/delete/', {'post': 'yes'}),
            ('/admin/core/news/', {'action': 'delete_selected', '_selected_action': str(self.news.pk), 'post': 'yes'}),
        ):
            with self.subTest(path=path):
                self.assert_login_required(self.client.post(path, payload))
        self.news.refresh_from_db()
        self.assertEqual(self.news.title, 'Authorization test')

    def test_normal_user_cannot_elevate_role_using_request_fields(self):
        self.client.force_login(self.reader)
        response = self.client.post(f'/admin/auth/user/{self.reader.pk}/change/', {
            'is_staff': 'on', 'is_superuser': 'on', 'role': 'admin',
            'user_id': self.admin.pk, '_auth_user_id': self.admin.pk,
        }, HTTP_X_USER_ROLE='admin', HTTP_X_FORWARDED_USER='access-admin')
        self.assert_login_required(response)
        self.reader.refresh_from_db()
        self.assertFalse(self.reader.is_staff)
        self.assertFalse(self.reader.is_superuser)

    def test_view_permission_does_not_grant_change_delete_or_user_access(self):
        self.client.force_login(self.viewer)
        self.assertEqual(self.client.get('/admin/core/news/').status_code, 200)
        self.assertEqual(self.client.get(f'/admin/core/news/{self.news.pk}/change/').status_code, 200)
        for path, method in (
            ('/admin/core/news/add/', 'get'),
            (f'/admin/core/news/{self.news.pk}/change/', 'post'),
            (f'/admin/core/news/{self.news.pk}/delete/', 'post'),
            ('/admin/auth/user/', 'get'),
        ):
            with self.subTest(path=path, method=method):
                self.assertEqual(getattr(self.client, method)(path, {'title': 'Unauthorized replacement'}).status_code, 403)
        self.news.refresh_from_db()
        self.assertEqual(self.news.title, 'Authorization test')

    def test_view_only_staff_cannot_bulk_delete(self):
        self.client.force_login(self.viewer)
        response = self.client.post('/admin/core/news/', {'action': 'delete_selected', '_selected_action': str(self.news.pk), 'post': 'yes'})
        self.assertIn(response.status_code, (200, 302, 403))
        self.assertTrue(News.objects.filter(pk=self.news.pk).exists())

    def test_inactive_superuser_cannot_access_backend(self):
        self.client.force_login(self.inactive)
        self.assert_login_required(self.client.get('/admin/auth/user/'))

    def test_role_cookie_cannot_replace_authentication(self):
        self.client.cookies['is_staff'] = 'true'
        self.client.cookies['is_superuser'] = 'true'
        self.client.cookies['user_id'] = str(self.admin.pk)
        self.client.cookies[settings.SESSION_COOKIE_NAME] = json.dumps({'_auth_user_id': self.admin.pk, 'is_staff': True})
        self.assert_login_required(self.client.get('/admin/'))

    def test_session_without_valid_authentication_hash_is_rejected(self):
        SessionStore = import_module(settings.SESSION_ENGINE).SessionStore
        session = SessionStore()
        session['_auth_user_id'] = str(self.admin.pk)
        session['_auth_user_backend'] = 'django.contrib.auth.backends.ModelBackend'
        session['_auth_user_hash'] = 'forged-test-value'
        session.save()
        self.client.cookies[settings.SESSION_COOKIE_NAME] = session.session_key
        self.assert_login_required(self.client.get('/admin/'))

    def test_sql_injection_cannot_authenticate_admin(self):
        for payload in ("' OR '1'='1' --", "access-admin'--", '" OR 1=1--'):
            with self.subTest(payload=payload):
                client = Client()
                response = client.post('/admin/login/', {'username': payload, 'password': payload})
                self.assertEqual(response.status_code, 200)
                self.assertNotIn('_auth_user_id', client.session)
                self.assert_login_required(client.get('/admin/auth/user/'))

    def test_public_request_fields_do_not_modify_database(self):
        for path in ('/', '/news/', '/news/authorization-test/', '/gallery/', '/news-gallery/'):
            self.assertEqual(self.client.get(path, {'id': self.news.pk, 'title': 'Unauthorized replacement', 'is_superuser': 'true', 'is_published': 'false', 'action': 'delete_selected'}).status_code, 200)
        self.news.refresh_from_db()
        self.assertEqual(self.news.title, 'Authorization test')
        self.assertTrue(self.news.is_published)

    def test_database_env_and_backup_download_routes_are_closed(self):
        paths = ('/db.sqlite3', '/db.sqlite3-wal', '/db.sqlite3-shm', '/.env', '/.env.bak', '/.runtime-data/db.sqlite3', '/.runtime-data/backups/', '/static/db.sqlite3', '/static/../db.sqlite3', '/media/../db.sqlite3', '/media/%2e%2e/db.sqlite3', '/media/..%5cdb.sqlite3', '/media/%00.jpg', '/media/image.jpg::$DATA', '/backup.sql', '/dump.sql', '/api/users/', '/api/news/', '/graphql/', '/__debug__/')
        for path in paths:
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertIn(response.status_code, (400, 404))
                self.assertFalse(response.content.startswith(b'SQLite format 3'))

    def test_admin_responses_are_not_publicly_cacheable(self):
        self.client.force_login(self.admin)
        response = self.client.get('/admin/auth/user/')
        self.assertEqual(response.status_code, 200)
        self.assertIn('private', response['Cache-Control'])
        self.assertIn('no-store', response['Cache-Control'])
