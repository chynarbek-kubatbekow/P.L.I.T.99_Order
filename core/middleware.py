import time
from datetime import datetime, timezone

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import DatabaseError
from django.db.models import F
from django.http import HttpResponse
from django.utils.crypto import salted_hmac
from django.utils.deprecation import MiddlewareMixin

from .models import AdminLoginThrottle


class RequestLimitsMiddleware(MiddlewareMixin):
    """Run before CSRF parses POST; auth is initialized by the request chain."""
    def process_view(self, request, view_func, view_args, view_kwargs):
        raw_length = request.META.get('CONTENT_LENGTH', '')
        if raw_length and (len(raw_length) > 20 or not raw_length.isascii() or not raw_length.isdigit()):
            return HttpResponse('Некорректный запрос.', status=400)
        length = int(raw_length or 0)
        maximum = 1024 * 1024
        view_name = request.resolver_match.view_name if request.resolver_match else ''
        if view_name in {'submit_feedback', 'admin:login'}:
            maximum = 65536
        upload_permissions = {
            'admin:core_news_add': 'core.add_news',
            'admin:core_news_change': 'core.change_news',
            'admin:core_galleryitem_add': 'core.add_galleryitem',
            'admin:core_galleryitem_change': 'core.change_galleryitem',
        }
        permission = upload_permissions.get(view_name)
        if permission and request.method == 'POST' and request.content_type == 'multipart/form-data':
            user = request.user
            if user.is_active and user.is_staff and user.has_perm(permission):
                maximum = 112 * 1024 * 1024
        if length > maximum:
            return HttpResponse('Запрос слишком большой для этой операции.', status=413)
        return None


class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Validate Host even for handlers that never build absolute URLs.
        request.get_host()
        response = self.get_response(request)
        response.setdefault('Content-Security-Policy', (
            "default-src 'self'; base-uri 'self'; object-src 'none'; "
            "frame-ancestors 'none'; form-action 'self'; "
            "script-src 'self' https://www.googletagmanager.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https://images.pexels.com https://www.google-analytics.com "
            "https://www.googletagmanager.com; "
            "connect-src 'self' https://www.google-analytics.com https://region1.google-analytics.com "
            "https://www.googletagmanager.com; "
            "frame-src https://www.youtube-nocookie.com https://player.vimeo.com https://www.google.com"
        ))
        response['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        response['X-Content-Type-Options'] = 'nosniff'
        # Browser tools can inspect anything delivered to the browser. Keep
        # private pages minimal, uncached and isolated from third-party scripts.
        private_page = request.path_info.startswith('/admin/') or request.path_info in {'/contacts/', '/contacts/feedback/'}
        if private_page:
            admin_page = request.path_info.startswith('/admin/')
            response['Content-Security-Policy'] = (
                "default-src 'self'; base-uri 'self'; object-src 'none'; "
                "frame-ancestors 'none'; form-action 'self'; script-src 'self'; "
                "style-src 'self' 'unsafe-inline'" + ('' if admin_page else ' https://fonts.googleapis.com') + '; '
                "font-src 'self'" + ('' if admin_page else ' https://fonts.gstatic.com') + '; '
                "img-src 'self' data:; connect-src 'self'; media-src 'self'; "
                + ("frame-src 'none'" if admin_page else 'frame-src https://www.google.com')
            )
            response['Cache-Control'] = 'no-store, private, max-age=0'
            response['Referrer-Policy'] = 'no-referrer'
            response['Cross-Origin-Resource-Policy'] = 'same-origin'
            response['X-Robots-Tag'] = 'noindex, nofollow, noarchive' if admin_page else 'noarchive'
        for header in ('Server', 'X-Powered-By', 'X-AspNet-Version'):
            if header in response:
                del response[header]
        return response


class AdminLoginThrottleMiddleware(MiddlewareMixin):
    def process_view(self, request, view_func, view_args, view_kwargs):
        if request.method != 'POST' or not request.resolver_match or request.resolver_match.view_name != 'admin:login':
            return None

        window = settings.ADMIN_LOGIN_WINDOW_SECONDS
        now = int(time.time())
        bucket = now // window
        # AuthenticationForm normalizes Unicode with NFKC. The limiter must use
        # the same identity (e.g. fullwidth letters and their ASCII equivalents).
        # Bound the input before normalization, matching Django's DoS precaution.
        raw_username = request.POST.get('username', '').strip()[:254]
        username = get_user_model().normalize_username(raw_username).casefold()
        limits = [
            ('ip', request.META.get('REMOTE_ADDR', ''), settings.ADMIN_LOGIN_IP_LIMIT),
            ('account', username, settings.ADMIN_LOGIN_ACCOUNT_LIMIT),
        ]
        try:
            for scope, identity, limit in limits:
                key = salted_hmac('admin-login-throttle', f'{scope}:{identity}:{bucket}', algorithm='sha256').hexdigest()
                # A unique primary key and conditional SQL UPDATE make the limit
                # atomic across workers, without a process-local cache.
                AdminLoginThrottle.objects.get_or_create(
                    key=key, defaults={'expires_at': datetime.fromtimestamp((bucket + 1) * window, timezone.utc)},
                )
                changed = AdminLoginThrottle.objects.filter(key=key, attempts__lt=limit).update(attempts=F('attempts') + 1)
                if not changed:
                    response = HttpResponse('Слишком много попыток входа. Попробуйте позже.', status=429)
                    response['Retry-After'] = str(window - now % window)
                    response['Cache-Control'] = 'no-store'
                    return response
        except DatabaseError:
            # If the shared limiter is unavailable, do not allow unthrottled login.
            response = HttpResponse('Вход временно недоступен.', status=503)
            response['Cache-Control'] = 'no-store'
            return response
        return None
