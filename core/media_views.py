from django.conf import settings
from django.http import FileResponse, Http404
from django.utils.http import http_date
from django.views.decorators.http import require_safe
from PIL import Image, UnidentifiedImageError

from .media_utils import resolve_media_file_path

MEDIA_CACHE_SECONDS = 60 * 60 * 24 * 30


@require_safe
def serve_media_file(request, path):
    if not settings.SERVE_MEDIA_FILES:
        raise Http404

    absolute_path = resolve_media_file_path(path)
    if not absolute_path:
        raise Http404

    content_types = {'.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.webp': 'image/webp'}
    content_type = content_types.get(absolute_path.suffix.lower())
    if not content_type:
        raise Http404
    try:
        with Image.open(absolute_path) as image:
            if Image.MIME.get(image.format) != content_type:
                raise Http404
            image.verify()
        stat = absolute_path.stat()
        stream = absolute_path.open('rb')
    except (OSError, ValueError, UnidentifiedImageError):
        raise Http404 from None

    response = FileResponse(
        stream,
        content_type=content_type,
    )
    response['Cache-Control'] = f'public, max-age={MEDIA_CACHE_SECONDS}, immutable'
    response['Content-Length'] = str(stat.st_size)
    response['Last-Modified'] = http_date(stat.st_mtime)
    response['X-Content-Type-Options'] = 'nosniff'
    response['Content-Security-Policy'] = "default-src 'none'; sandbox"
    return response
