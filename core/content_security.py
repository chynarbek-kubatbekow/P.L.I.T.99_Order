"""Allow lists shared by model validation and rendering of existing content."""
import re
from html import unescape
from urllib.parse import parse_qs, urlsplit

import nh3
from django.core.exceptions import ValidationError


DEFAULT_GRADIENT = 'linear-gradient(135deg,#0D3060,#1668C0)'
GRADIENT_RE = re.compile(
    r'linear-gradient\(\s*-?\d{1,3}deg\s*,\s*#[0-9a-fA-F]{3,8}\s*,\s*#[0-9a-fA-F]{3,8}\s*\)'
)
CLEANER = nh3.Cleaner(
    tags={'p', 'br', 'strong', 'b', 'em', 'i', 'u', 's', 'h2', 'h3', 'h4',
          'ul', 'ol', 'li', 'blockquote', 'a', 'pre', 'code', 'hr',
          'table', 'thead', 'tbody', 'tr', 'th', 'td', 'span', 'div'},
    attributes={'a': {'href', 'title'}},
    clean_content_tags={'script', 'style', 'iframe', 'object', 'svg', 'math', 'template'},
    url_schemes={'https', 'http', 'mailto'},
    link_rel='noopener noreferrer',
)


def decode_html_entities(text, max_passes=5):
    for _ in range(max_passes):
        decoded = unescape(text)
        if decoded == text:
            break
        text = decoded
    return text


def sanitize_rich_text(value):
    return CLEANER.clean(decode_html_entities(value or ''))


def safe_gradient(value):
    return value if isinstance(value, str) and GRADIENT_RE.fullmatch(value) else DEFAULT_GRADIENT


def validate_gradient(value):
    if not GRADIENT_RE.fullmatch(value):
        raise ValidationError('Используйте linear-gradient с углом в deg и двумя HEX-цветами.')


def video_embed_url(value):
    """Canonical HTTPS embeds only; never fetch a URL on the server."""
    try:
        url = urlsplit(value)
        if url.scheme != 'https' or url.username or url.password or url.port not in (None, 443):
            return ''
        host = (url.hostname or '').lower()
        if host in {'youtube.com', 'www.youtube.com', 'www.youtube-nocookie.com', 'youtu.be'}:
            if host == 'youtu.be':
                video_id = url.path.lstrip('/')
            elif url.path == '/watch':
                video_id = parse_qs(url.query).get('v', [''])[0]
            elif url.path.startswith(('/embed/', '/shorts/')):
                video_id = url.path.split('/')[2]
            else:
                return ''
            if re.fullmatch(r'[a-zA-Z0-9_-]{11}', video_id):
                return f'https://www.youtube-nocookie.com/embed/{video_id}'
        elif host in {'vimeo.com', 'www.vimeo.com', 'player.vimeo.com'}:
            match = re.fullmatch(r'/(?:video/)?(\d{1,12})/?', url.path)
            if match:
                return f'https://player.vimeo.com/video/{match[1]}'
    except (ValueError, IndexError):
        pass
    return ''


def validate_video_url(value):
    if value and not video_embed_url(value):
        raise ValidationError('Укажите HTTPS-ссылку на видео YouTube или Vimeo.')
