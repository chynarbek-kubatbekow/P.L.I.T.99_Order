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
