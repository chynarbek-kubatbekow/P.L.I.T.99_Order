import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlencode
from concurrent.futures import ThreadPoolExecutor

import imageio_ffmpeg
from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import DatabaseError, close_old_connections
from django.test import Client, TestCase, TransactionTestCase, override_settings

from .feedback_security import feedback_cipher
from .models import AdminLoginThrottle, GalleryItem, News, PrivateFeedback
from .video_uploads import normalize_video


@override_settings(SECURE_SSL_REDIRECT=False, FEEDBACK_ENCRYPTION_KEYS=[Fernet.generate_key().decode('ascii')])
class FeedbackSecurityTests(TestCase):
    def post(self, message='A private suggestion for the school.', **extra):
        return self.client.post('/contacts/feedback/', urlencode({'message': message, **extra}), content_type='application/x-www-form-urlencoded')

    def test_encrypted_at_rest_and_not_reflected(self):
        marker = '<script>alert("STORED_XSS")</script>\n\' OR 1=1; DROP TABLE core_news; --'
        response = self.post(marker)
        self.assertEqual(response.status_code, 302)
        row = PrivateFeedback.objects.get()
        self.assertNotIn(marker, row.encrypted_message)
        self.assertEqual(feedback_cipher().decrypt(row.encrypted_message.encode()).decode(), marker)
        self.assertEqual(News.objects.count(), 0)
        self.assertNotIn('STORED_XSS', self.client.get(response.url).content.decode())

    def test_ciphertext_tampering_detected(self):
        self.post()
        token = bytearray(PrivateFeedback.objects.get().encrypted_message.encode())
        token[len(token)//2] = ord('X') if token[len(token)//2] != ord('X') else ord('Y')
        with self.assertRaises(InvalidToken):
            feedback_cipher().decrypt(bytes(token))

    def test_csrf_and_cross_origin(self):
        client = Client(enforce_csrf_checks=True)
        self.assertEqual(client.post('/contacts/feedback/', {'message': 'No csrf token here'}).status_code, 403)
        client.get('/contacts/')
        token = client.cookies['csrftoken'].value
        response = client.post('/contacts/feedback/', urlencode({'message': 'A valid token with forged origin', 'csrfmiddlewaretoken': token}),
                               content_type='application/x-www-form-urlencoded', HTTP_ORIGIN='https://attacker.invalid')
        self.assertEqual(response.status_code, 403)
        self.assertEqual(PrivateFeedback.objects.count(), 0)

    def test_valid_browser_form_with_csrf(self):
        client = Client(enforce_csrf_checks=True)
        client.get('/contacts/')
        response = client.post('/contacts/feedback/', urlencode({'message': 'A valid suggestion with csrf', 'csrfmiddlewaretoken': client.cookies['csrftoken'].value}), content_type='application/x-www-form-urlencoded')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(PrivateFeedback.objects.count(), 1)

    def test_no_public_read_update_delete(self):
        self.post()
        for method in ('get', 'put', 'patch', 'delete'):
            self.assertEqual(getattr(self.client, method)('/contacts/feedback/').status_code, 405)
        for path in ('/feedback/', '/feedback/1/', '/api/feedback/', '/media/feedback/1'):
            self.assertEqual(self.client.get(path).status_code, 404)
        row = PrivateFeedback.objects.get()
        with self.assertRaises(ValidationError):
            row.save()

    def test_schema_duplicates_size_and_honeypot(self):
        self.assertEqual(self.post('short').status_code, 400)
        self.assertEqual(self.post('x' * 4001).status_code, 400)
        self.assertEqual(self.post('message\x00control').status_code, 400)
        self.assertEqual(self.post(role='admin').status_code, 400)
        self.assertEqual(self.client.post('/contacts/feedback/', 'message=first+message&message=other+message', content_type='application/x-www-form-urlencoded').status_code, 400)
        self.assertEqual(self.post('x' * 70000).status_code, 413)
        self.assertEqual(self.client.post('/contacts/feedback/', '{}', content_type='application/json').status_code, 415)
        self.assertEqual(self.post(website='bot.invalid').status_code, 302)
        self.assertEqual(PrivateFeedback.objects.count(), 0)

    @override_settings(FEEDBACK_IP_LIMIT=2)
    def test_rate_limit_and_forwarded_ip_cannot_bypass(self):
        self.post()
        self.post()
        response = self.client.post('/contacts/feedback/', urlencode({'message': 'Cannot bypass limit using headers'}), content_type='application/x-www-form-urlencoded', HTTP_X_FORWARDED_FOR='1.2.3.4')
        self.assertEqual(response.status_code, 429)
        self.assertEqual(PrivateFeedback.objects.count(), 2)

    def test_db_failure_is_closed_and_does_not_echo_message(self):
        with patch('core.views.take_feedback_quota', side_effect=DatabaseError('SECRET_DB_MARKER')):
            response = self.post('PRIVATE_INPUT_MARKER')
        self.assertEqual(response.status_code, 503)
        self.assertNotIn(b'SECRET_DB_MARKER', response.content)
        self.assertNotIn(b'PRIVATE_INPUT_MARKER', response.content)

    @override_settings(IS_PRODUCTION=True, FEEDBACK_ENCRYPTION_KEYS=[])
    def test_production_requires_separate_key(self):
        self.assertEqual(self.post().status_code, 503)
        self.assertEqual(PrivateFeedback.objects.count(), 0)

    def test_key_rotation_reads_old_messages(self):
        self.post()
        row = PrivateFeedback.objects.get()
        old_keys = list(settings.FEEDBACK_ENCRYPTION_KEYS)
        with override_settings(FEEDBACK_ENCRYPTION_KEYS=[Fernet.generate_key().decode(), *old_keys]):
            self.assertTrue(feedback_cipher().decrypt(row.encrypted_message.encode()))
        with override_settings(FEEDBACK_ENCRYPTION_KEYS=[Fernet.generate_key().decode()]):
            with self.assertRaises(InvalidToken):
                feedback_cipher().decrypt(row.encrypted_message.encode())

    def test_admin_permission_and_escaped_message(self):
        marker = '<script>alert("STAFF_XSS")</script>'
        self.post(marker)
        row = PrivateFeedback.objects.get()
        url = f'/admin/core/privatefeedback/{row.pk}/change/'
        self.assertEqual(self.client.get(url).status_code, 302)
        staff = get_user_model().objects.create_user('reader', is_staff=True)
        self.client.force_login(staff)
        self.assertEqual(self.client.get(url).status_code, 403)
        staff.user_permissions.add(Permission.objects.get(codename='view_privatefeedback'))
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '&lt;script&gt;')
        self.assertNotContains(response, marker)
        self.assertEqual(self.client.post(url, {'encrypted_message': 'replaced'}).status_code, 403)
        self.assertEqual(self.client.post(f'/admin/core/privatefeedback/{row.pk}/delete/', {'post': 'yes'}).status_code, 403)

    def test_no_analytics_or_public_credit_elsewhere(self):
        response = self.client.get('/contacts/')
        self.assertNotContains(response, 'googletagmanager.com/gtag/js')
        self.assertContains(response, 'footer-credit')
        self.assertIn('no-store', response['Cache-Control'])
        self.assertNotContains(self.client.get('/'), 'class="footer-credit"')

    def test_unicode_message_and_global_quota(self):
        self.assertEqual(self.post('Отзыв ' * 600).status_code, 302)
        with override_settings(FEEDBACK_GLOBAL_LIMIT=1):
            response = self.client.post('/contacts/feedback/', urlencode({'message': 'A different visitor cannot bypass global quota'}), content_type='application/x-www-form-urlencoded', REMOTE_ADDR='192.0.2.99')
            self.assertEqual(response.status_code, 429)
        self.assertEqual(PrivateFeedback.objects.count(), 1)

    @override_settings(FEEDBACK_IP_LIMIT=1, FEEDBACK_GLOBAL_LIMIT=2)
    def test_rejected_requests_do_not_exhaust_other_visitors_quota(self):
        self.assertEqual(self.post().status_code, 302)
        self.assertEqual(self.post().status_code, 429)
        response = self.client.post('/contacts/feedback/', urlencode({'message': 'Another visitor may still send'}), content_type='application/x-www-form-urlencoded', REMOTE_ADDR='192.0.2.20')
        self.assertEqual(response.status_code, 302)
        count = AdminLoginThrottle.objects.count()
        for suffix in range(10):
            self.assertEqual(self.client.post('/contacts/feedback/', urlencode({'message': 'The global limit is now reached'}), content_type='application/x-www-form-urlencoded', REMOTE_ADDR=f'192.0.2.{100+suffix}').status_code, 429)
        self.assertEqual(AdminLoginThrottle.objects.count(), count)

    def test_key_file_cannot_be_public_and_command_never_replaces_it(self):
        from django.core.management import call_command
        from django.core.management.base import CommandError
        from io import StringIO
        with tempfile.TemporaryDirectory(prefix='plit-feedback-key-') as work:
            path = Path(work) / 'feedback.key'
            with override_settings(FEEDBACK_ENCRYPTION_KEYS=[], FEEDBACK_ENCRYPTION_KEY_FILE=str(path)):
                output = StringIO()
                call_command('create_feedback_key', stdout=output)
                original = path.read_bytes()
                self.assertNotIn(original.decode(), output.getvalue())
                self.assertEqual(self.post().status_code, 302)
                with self.assertRaises(CommandError):
                    call_command('create_feedback_key', stdout=output)
                self.assertEqual(path.read_bytes(), original)
        with override_settings(FEEDBACK_ENCRYPTION_KEYS=[], FEEDBACK_ENCRYPTION_KEY_FILE=str(settings.MEDIA_ROOT / 'public.key')):
            self.assertEqual(self.post().status_code, 503)


@override_settings(SECURE_SSL_REDIRECT=False)
class UploadedVideoTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.work = tempfile.TemporaryDirectory(prefix='plit-video-test-')
        cls.media = override_settings(MEDIA_ROOT=Path(cls.work.name) / 'media')
        cls.media.enable()
        target = Path(cls.work.name) / 'test.mp4'
        subprocess.run([imageio_ffmpeg.get_ffmpeg_exe(), '-nostdin', '-loglevel', 'error', '-f', 'lavfi', '-i',
                        'color=c=blue:s=320x240:r=10', '-t', '0.5', '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-y', str(target)],
                       timeout=15, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.video_bytes = target.read_bytes()

    @classmethod
    def tearDownClass(cls):
        cls.media.disable()
        cls.work.cleanup()
        super().tearDownClass()

    def upload(self):
        return SimpleUploadedFile('school.mp4', self.video_bytes, content_type='text/html')

    def test_real_video_news_and_gallery_and_range(self):
        news = News.objects.create(title='Video', slug='video-test', excerpt='Test', content='Text', video_file=self.upload())
        item = GalleryItem.objects.create(title='Video', media_type='video', video_file=self.upload())
        self.assertContains(self.client.get(news.get_absolute_url()), '<video')
        self.assertContains(self.client.get('/gallery/'), item.video_file.url)
        self.assertContains(self.client.get('/news-gallery/'), item.video_file.url)
        response = self.client.get(news.video_file.url, HTTP_RANGE='bytes=0-31')
        self.assertEqual(response.status_code, 206)
        self.assertEqual(len(b''.join(response.streaming_content)), 32)
        self.assertEqual(response['Content-Type'], 'video/mp4')
        for value in ('bytes=99999999-', 'bytes=0-1,5-9', 'bytes=' + '9'*5000 + '-'):
            self.assertEqual(self.client.get(news.video_file.url, HTTP_RANGE=value).status_code, 416)
        self.assertEqual(self.client.head(news.video_file.url).status_code, 200)

    def test_draft_and_orphan_video_not_public(self):
        news = News.objects.create(title='Draft', slug='video-draft', excerpt='Test', content='Text', video_file=self.upload(), is_published=False)
        self.assertEqual(self.client.get(news.video_file.url).status_code, 404)
        staff = get_user_model().objects.create_user('editor', is_staff=True)
        self.client.force_login(staff)
        self.assertEqual(self.client.get(news.video_file.url).status_code, 404)
        staff.user_permissions.add(Permission.objects.get(codename='view_news'))
        response = self.client.get(news.video_file.url)
        self.assertEqual(response.status_code, 200)
        response.close()
        url = news.video_file.url
        news.delete()
        self.assertEqual(self.client.get(url).status_code, 404)

    def test_fake_video_and_oversize_rejected(self):
        for name, body in [('attack.mp4', b'<html><script>alert(1)</script></html>'), ('attack.webm', b'not-video'), ('attack.svg', b'<svg/>')]:
            with self.subTest(name=name), self.assertRaises(ValidationError):
                normalize_video(SimpleUploadedFile(name, body))
        with override_settings(MAX_UPLOAD_VIDEO_BYTES=10), self.assertRaises(ValidationError):
            normalize_video(self.upload())

    def test_conflicting_sources_and_wrong_type_rejected(self):
        with self.assertRaises(ValidationError):
            GalleryItem.objects.create(media_type='video', video_url='https://youtu.be/abcdefghijk', video_file=self.upload())
        with self.assertRaises(ValidationError):
            GalleryItem.objects.create(media_type='photo', video_file=self.upload())

    def test_upload_via_real_admin_form(self):
        from django.utils import timezone
        user = get_user_model().objects.create_superuser('video-admin', password='Test-only-video-4f#long')
        self.client.force_login(user)
        response = self.client.post('/admin/core/news/add/', {
            'title': 'Uploaded from admin', 'slug': 'admin-video', 'excerpt': 'Summary', 'content': 'Text',
            'cover_emoji': 'N', 'cover_gradient': 'linear-gradient(135deg,#0D3060,#1668C0)',
            'video_file': self.upload(), 'is_published': 'on',
            'published_at_0': timezone.localdate().isoformat(), 'published_at_1': '12:00:00', '_save': 'Save',
        })
        self.assertEqual(response.status_code, 302, response.context['adminform'].form.errors if response.status_code == 200 else '')
        news = News.objects.get(slug='admin-video')
        self.assertTrue(news.video_file.name.endswith('.mp4'))
        response = self.client.get(news.video_file.url)
        self.assertEqual(response.status_code, 200)
        response.close()

    def test_decoder_timeout_and_long_duration_fail_closed(self):
        with patch('core.video_uploads.subprocess.run', side_effect=subprocess.TimeoutExpired('ffmpeg', 45)), self.assertRaises(ValidationError):
            normalize_video(self.upload())
        with patch('core.video_uploads.mp4_duration', return_value=121), self.assertRaises(ValidationError):
            normalize_video(self.upload())

    def test_webm_is_transcoded_and_playlist_is_rejected(self):
        path = Path(self.work.name) / 'source.webm'
        subprocess.run([imageio_ffmpeg.get_ffmpeg_exe(), '-nostdin', '-loglevel', 'error', '-f', 'lavfi', '-i',
                        'color=c=blue:s=160x120:r=5', '-t', '0.4', '-c:v', 'libvpx-vp9', '-y', str(path)],
                       timeout=15, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        result = normalize_video(SimpleUploadedFile('source.webm', path.read_bytes()))
        self.assertEqual(result.read(12)[4:8], b'ftyp')
        playlist = b'#EXTM3U\n#EXTINF:1,\nhttp://127.0.0.1:9/private\n'
        with self.assertRaises(ValidationError):
            normalize_video(SimpleUploadedFile('attack.mp4', playlist))


@override_settings(SECURE_SSL_REDIRECT=False, FEEDBACK_IP_LIMIT=3, FEEDBACK_GLOBAL_LIMIT=20,
                   FEEDBACK_ENCRYPTION_KEYS=[Fernet.generate_key().decode('ascii')])
class ConcurrentFeedbackTests(TransactionTestCase):
    def test_concurrent_writes_do_not_exceed_quota(self):
        def attempt(index):
            close_old_connections()
            try:
                response = Client().post('/contacts/feedback/', urlencode({'message': f'Synthetic concurrent feedback {index}'}), content_type='application/x-www-form-urlencoded')
                return response.status_code
            finally:
                close_old_connections()
        with ThreadPoolExecutor(max_workers=4) as executor:
            outcomes = list(executor.map(attempt, range(8)))
        self.assertTrue(all(code in {302, 429, 503} for code in outcomes))
        self.assertGreater(outcomes.count(302), 0)
        self.assertLessEqual(outcomes.count(302), 3)
        self.assertEqual(PrivateFeedback.objects.count(), outcomes.count(302))
