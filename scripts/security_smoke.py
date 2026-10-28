"""Local HTTP checks against Waitress, using only a disposable database.

Run: python scripts/security_smoke.py
Use --serve to keep the isolated site available for manual browser verification.
"""
import argparse
import http.client
import os
from pathlib import Path
import secrets
import socket
import sys
import tempfile
import threading
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serve', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(root))
    with tempfile.TemporaryDirectory(prefix='plit99-security-') as directory:
        os.environ.update({
            'DJANGO_SETTINGS_MODULE': 'plit99_project.settings',
            'APP_ENV': 'local', 'DEBUG': 'False',
            'SECRET_KEY': secrets.token_urlsafe(64),
            'APP_DATA_DIR': directory,
            'DATABASE_URL': f'sqlite:///{Path(directory).as_posix()}/smoke.sqlite3',
            'ALLOWED_HOSTS': '127.0.0.1,localhost',
            'SECURE_SSL_REDIRECT': 'False', 'TRUST_PROXY_HEADERS': 'False',
            'SESSION_COOKIE_SECURE': 'False', 'CSRF_COOKIE_SECURE': 'False',
            'SERVE_MEDIA_FILES': 'True',
        })
        import django
        django.setup()
        from django.core.management import call_command
        from django.core.wsgi import get_wsgi_application
        from django.db import connections
        from waitress import create_server
        from core.models import News

        call_command('migrate', verbosity=0, interactive=False)
        news = News.objects.create(title='Security test news', slug='security-test', excerpt='Test content only', content='<p>Allowed news text.</p>')
        News.objects.filter(pk=news.pk).update(content='<p>Allowed news text.</p><script>HTTP_XSS_MARKER()</script>')
        server = create_server(
            get_wsgi_application(), host='127.0.0.1', port=0, threads=4,
            max_request_body_size=12582912, max_request_header_size=32768,
            channel_timeout=60, connection_limit=100,
        )
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        port = server.effective_port
        base = f'http://127.0.0.1:{port}'
        checked = 0

        def check(path, expected, *, method='GET', headers=None):
            nonlocal checked
            request = Request(base + path, method=method, headers=headers or {})
            try:
                response = urlopen(request, timeout=10)
            except HTTPError as error:
                response = error
            with response:
                body = response.read()
                assert response.status == expected, (path, response.status, expected)
                checked += 1
                return body, response.headers

        try:
            for path in ('/', '/education/', '/contacts/', '/news-gallery/', '/admin/login/'):
                check(path, 200)
            body, headers = check('/news/security-test/', 200)
            assert b'HTTP_XSS_MARKER' not in body
            assert b'<p>Allowed news text.</p>' in body
            assert "script-src 'self'" in headers['Content-Security-Policy']
            body, _ = check('/ddd//', 404)
            assert b'URLconf' not in body and b'admin/' not in body and b'DEBUG' not in body
            for path in ('/.env', '/.git/config', '/db.sqlite3', '/media/../manage.py', '/media/%2e%2e/.env'):
                check(path, 404)
            check('/healthz/', 400, headers={'Host': 'attacker.invalid'})
            check('/admin/login/', 403, method='POST')
            for path in ('/static/css/style.css', '/static/js/main.js', '/static/js/career-test.js', '/static/js/analytics-init.js', '/static/admin/css/base.css'):
                check(path, 200)
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
            connection.request('POST', '/admin/login/', headers={'Content-Length': '12582913'})
            response = connection.getresponse()
            assert response.status == 413, response.status
            checked += 1
            response.read()
            connection.close()
            # Direct Waitress framing checks. These do not certify an IIS/CDN
            # chain: each deployed proxy must be checked separately.
            malformed = (
                (b'Content-Length: 0\r\nContent-Length: 5\r\n', b'', 400),
                (b'Content-Length: -1\r\n', b'', 400),
                (b'Transfer-Encoding: gzip\r\n', b'', 501),
                (b'Transfer-Encoding: chunked\r\n', b'not-hex\r\n', 400),
            )
            for extra_headers, body, expected in malformed:
                with socket.create_connection(('127.0.0.1', port), timeout=5) as raw:
                    raw.sendall(
                        b'POST /healthz/ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n'
                        + extra_headers + b'\r\n' + body
                    )
                    response_data = b''
                    while b'\r\n' not in response_data:
                        chunk = raw.recv(4096)
                        assert chunk, 'No HTTP framing error response'
                        response_data += chunk
                        assert len(response_data) < 65536
                    status = int(response_data.split(b' ', 2)[1])
                    assert status == expected, ('malformed-framing', status, expected)
                    checked += 1

            for path in ('/static/%2e%2e/.env', '/media/%252e%252e/.env', '/media/..%5cdb.sqlite3', '/.git/HEAD', '/.git/index', '/.svn/entries', '/.hg/store/00manifest.i', '/.runtime-data/backups/', '/backup.sql'):
                check(path, 404)
            for origin in ('https://attacker.invalid', 'null'):
                _, headers = check('/healthz/', 200, headers={'Origin': origin})
                assert headers.get('Access-Control-Allow-Origin') is None
                assert headers.get('Access-Control-Allow-Credentials') is None
            _, headers = check('/healthz/', 200, headers={
                'X-Original-URL': '/admin/auth/user/',
                'X-Rewrite-URL': '/admin/auth/user/',
                'X-Forwarded-Host': 'attacker.invalid',
            })
            print(f'HTTP security smoke: {checked} checks passed.', flush=True)
            if args.serve:
                print(f'Isolated browser preview: {base}', flush=True)
                print('Only synthetic content; stop with Ctrl+C.', flush=True)
                while True:
                    time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            server.close()
            connections.close_all()


if __name__ == '__main__':
    main()
