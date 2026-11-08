"""Loopback-only feature checks for the disposable security_smoke database."""
import html
import http.client
import struct
import subprocess
import tempfile
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlencode, urlsplit


def run_feature_checks(base, *, large_upload=False):
    import imageio_ffmpeg
    from django.conf import settings
    from django.contrib.auth import get_user_model
    from django.contrib.auth.models import Permission
    from django.test import Client
    from django.utils import timezone
    from core.feedback_security import feedback_cipher
    from core.models import News, PrivateFeedback

    url = urlsplit(base)
    assert url.scheme == 'http' and url.hostname == '127.0.0.1'
    checked = 0

    def request(method, path, expected, *, body=None, headers=None):
        nonlocal checked
        conn = http.client.HTTPConnection(url.hostname, url.port, timeout=60)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            response = conn.getresponse()
            content = response.read()
            result_headers = dict(response.getheaders())
            assert response.status == expected, ('HTTP feature status', path, response.status, expected)
            checked += 1
            return content, result_headers
        finally:
            conn.close()

    def cookie_from(headers):
        cookie = SimpleCookie()
        cookie.load(headers.get('Set-Cookie', ''))
        return cookie['csrftoken'].value

    def assert_private(headers):
        assert 'no-store' in headers['Cache-Control']
        assert headers['Referrer-Policy'] == 'same-origin'
        assert "script-src 'self';" in headers['Content-Security-Policy']
        assert not any(name in headers for name in ('Server', 'X-Powered-By', 'Access-Control-Allow-Origin'))

    body, headers = request('GET', '/contacts/', 200)
    assert_private(headers)
    assert b'googletagmanager.com/gtag/js' not in body
    token = cookie_from(headers)
    public_headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Cookie': f'csrftoken={token}'}
    marker = 'HTTP_PRIVATE_SENTINEL <script>alert(1)</script> \' OR 1=1; DROP TABLE core_news; --'
    payload = urlencode({'message': marker, 'csrfmiddlewaretoken': token})
    request('POST', '/contacts/feedback/', 403, body=urlencode({'message': marker}), headers=public_headers)
    request('POST', '/contacts/feedback/', 403, body=payload, headers={**public_headers, 'Origin': 'https://attacker.invalid'})
    _, headers = request('POST', '/contacts/feedback/', 302, body=payload, headers=public_headers)
    assert_private(headers)
    row = PrivateFeedback.objects.latest('pk')
    assert marker not in row.encrypted_message
    assert feedback_cipher().decrypt(row.encrypted_message.encode()).decode() == marker
    public_body, _ = request('GET', '/contacts/?sent=1', 200)
    assert b'HTTP_PRIVATE_SENTINEL' not in public_body
    request('GET', '/contacts/feedback/', 405)
    request('POST', '/contacts/feedback/', 400, body=urlencode({'message': marker, 'is_superuser': 'on', 'csrfmiddlewaretoken': token}), headers=public_headers)
    request('GET', f'/admin/core/privatefeedback/{row.pk}/change/', 302)

    user_model = get_user_model()
    reader = user_model.objects.create_user('http-review-reader', is_staff=True)
    client = Client()
    client.force_login(reader)
    session_cookie = f'{settings.SESSION_COOKIE_NAME}={client.cookies[settings.SESSION_COOKIE_NAME].value}'
    detail = f'/admin/core/privatefeedback/{row.pk}/change/'
    request('GET', detail, 403, headers={'Cookie': session_cookie})
    reader.user_permissions.add(Permission.objects.get(codename='view_privatefeedback'))
    body, headers = request('GET', detail, 200, headers={'Cookie': session_cookie})
    assert_private(headers)
    assert html.escape(marker).encode() in body
    assert b'<script>alert(1)</script>' not in body
    assert row.encrypted_message.encode() not in body
    admin_token = cookie_from(headers)
    request('POST', detail, 403, body=urlencode({'encrypted_message': 'replacement', 'csrfmiddlewaretoken': admin_token}),
            headers={'Content-Type': 'application/x-www-form-urlencoded', 'Cookie': session_cookie + f'; csrftoken={admin_token}'})
    row.refresh_from_db()
    assert feedback_cipher().decrypt(row.encrypted_message.encode()).decode() == marker
    reader.user_permissions.clear()
    request('GET', detail, 403, headers={'Cookie': session_cookie})
    for route in ('/.runtime-data/.feedback-key', '/media/.feedback-key', '/static/.env', '/api/feedback/'):
        request('GET', route, 404)

    if large_upload:
        # Real 100 MiB multipart request, streamed in chunks. The synthetic MP4
        # contains a valid short clip and an inert MP4 free box to exercise the
        # size boundary without minutes of costly high-resolution encoding.
        admin = user_model.objects.create_superuser('http-video-admin')
        client.force_login(admin)
        session_cookie = f'{settings.SESSION_COOKIE_NAME}={client.cookies[settings.SESSION_COOKIE_NAME].value}'
        _, headers = request('GET', '/admin/core/news/add/', 200, headers={'Cookie': session_cookie})
        admin_token = cookie_from(headers)
        cookie = session_cookie + f'; csrftoken={admin_token}'
        with tempfile.TemporaryDirectory(prefix='plit-http-100m-') as work:
            video = Path(work) / 'video.mp4'
            subprocess.run([imageio_ffmpeg.get_ffmpeg_exe(), '-nostdin', '-hide_banner', '-loglevel', 'error',
                            '-f', 'lavfi', '-i', 'color=c=blue:s=160x120:r=5', '-t', '0.4', '-c:v', 'libx264',
                            '-pix_fmt', 'yuv420p', '-y', str(video)],
                           check=True, timeout=15, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            original = video.read_bytes()

            def upload_video(size, slug):
                nonlocal checked
                # Sparse zero-filled free box is skipped by the decoder but all
                # bytes are actually sent over HTTP and parsed by Django.
                with video.open('wb') as stream:
                    stream.write(original)
                    stream.write(struct.pack('>I4s', size - len(original), b'free'))
                    stream.truncate(size)
                boundary = 'plit99-synthetic-boundary'
                fields = {'csrfmiddlewaretoken': admin_token, 'title': 'HTTP upload boundary', 'slug': slug,
                          'excerpt': 'Synthetic', 'content': 'Synthetic content', 'cover_emoji': 'N',
                          'cover_gradient': 'linear-gradient(135deg,#0D3060,#1668C0)', 'is_published': 'on',
                          'published_at_0': timezone.localdate().isoformat(), 'published_at_1': '12:00:00', '_save': 'Save'}
                prefix = ''.join(f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n' for key, value in fields.items()).encode()
                prefix += (f'--{boundary}\r\nContent-Disposition: form-data; name="video_file"; filename="clip.mp4"\r\nContent-Type: video/mp4\r\n\r\n').encode()
                suffix = f'\r\n--{boundary}--\r\n'.encode()
                conn = http.client.HTTPConnection(url.hostname, url.port, timeout=60)
                try:
                    conn.putrequest('POST', '/admin/core/news/add/')
                    conn.putheader('Cookie', cookie)
                    conn.putheader('Content-Type', f'multipart/form-data; boundary={boundary}')
                    conn.putheader('Content-Length', str(len(prefix) + size + len(suffix)))
                    conn.endheaders()
                    conn.send(prefix)
                    with video.open('rb') as stream:
                        while chunk := stream.read(1024 * 1024):
                            conn.send(chunk)
                    conn.send(suffix)
                    response = conn.getresponse()
                    content = response.read()
                    checked += 1
                    return response.status, content
                finally:
                    conn.close()

            limit = 100 * 1024 * 1024
            status, _ = upload_video(limit, 'exact-100m-upload')
            assert status == 302, ('100 MiB upload', status)
            news = News.objects.get(slug='exact-100m-upload')
            body, headers = request('GET', news.video_file.url, 206, headers={'Range': 'bytes=0-31'})
            assert len(body) == 32 and headers['Content-Type'] == 'video/mp4'
            status, body = upload_video(limit + 1, 'over-100m-upload')
            assert status == 200 and '100 МБ'.encode() in body, ('oversized admin validation', status)
            assert not News.objects.filter(slug='over-100m-upload').exists()
        print('Large upload boundary: 100 MiB accepted; 100 MiB + 1 byte rejected; actual loopback multipart.', flush=True)
    print(f'HTTP private feature checks: {checked} passed.', flush=True)
    return checked
