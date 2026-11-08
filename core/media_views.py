from django.conf import settings
from django.http import FileResponse, Http404, HttpResponse, StreamingHttpResponse
import re
from django.utils.http import http_date
from django.views.decorators.http import require_safe
from PIL import Image, UnidentifiedImageError

from .media_utils import resolve_media_file_path


def serve_video(request, path, absolute_path):
    from .models import News, GalleryItem
    # A file on disk isn't permission to publish it. Draft videos require the
    # respective admin view permission; anonymous visitors cannot fetch them.
    published = News.objects.filter(video_file=path, is_published=True).exists() or GalleryItem.objects.filter(video_file=path, is_published=True).exists()
    if not published:
        user = request.user
        allowed = user.is_active and user.is_staff and (
            (user.has_perm('core.view_news') and News.objects.filter(video_file=path).exists()) or
            (user.has_perm('core.view_galleryitem') and GalleryItem.objects.filter(video_file=path).exists()))
        if not allowed:
            raise Http404
    with absolute_path.open('rb') as probe:
        header = probe.read(12)
    if len(header) < 12 or header[4:8] != b'ftyp':
        raise Http404
    size = absolute_path.stat().st_size
    start, end = 0, size - 1
    range_header = request.headers.get('Range')
    if range_header:
        match = re.fullmatch(r'bytes=([0-9]{0,20})-([0-9]{0,20})', range_header)
        if not match or not any(match.groups()):
            response = HttpResponse(status=416)
            response['Content-Range'] = f'bytes */{size}'
            return response
        left, right = match.groups()
        if left:
            start = int(left)
            end = min(int(right), size - 1) if right else size - 1
        else:
            start = max(0, size - int(right))
        if start > end or start >= size:
            response = HttpResponse(status=416)
            response['Content-Range'] = f'bytes */{size}'
            return response

    def chunks():
        with absolute_path.open('rb') as stream:
            stream.seek(start)
            remaining = end - start + 1
            while remaining:
                chunk = stream.read(min(65536, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                yield chunk

    response = StreamingHttpResponse(chunks() if request.method != 'HEAD' else (),
                                     status=206 if range_header else 200, content_type='video/mp4')
    response['Accept-Ranges'] = 'bytes'
    response['Content-Length'] = str(end - start + 1)
    if range_header:
        response['Content-Range'] = f'bytes {start}-{end}/{size}'
    response['Cache-Control'] = 'no-store'
    response['Content-Security-Policy'] = "default-src 'none'; sandbox"
    response['X-Content-Type-Options'] = 'nosniff'
    return response

MEDIA_CACHE_SECONDS = 60 * 60 * 24 * 30


@require_safe
def serve_media_file(request, path):
    if not settings.SERVE_MEDIA_FILES:
        raise Http404

    absolute_path = resolve_media_file_path(path)
    if not absolute_path:
        raise Http404

    if re.fullmatch(r'videos/[0-9a-f]{32}\.mp4', path):
        return serve_video(request, path, absolute_path)

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
