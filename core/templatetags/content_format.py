import re

from django import template
from django.template.defaultfilters import linebreaks
from django.utils.safestring import mark_safe
from core.content_security import decode_html_entities, sanitize_rich_text, safe_gradient, video_embed_url


register = template.Library()

GENERIC_HTML_TAG_RE = re.compile(r"<\s*/?\s*[a-zA-Z][^>]*>")


@register.filter(is_safe=True)
def render_rich_text(value):
    text = (value or "").strip()
    if not text:
        return ""

    decoded_text = decode_html_entities(text)
    if GENERIC_HTML_TAG_RE.search(decoded_text):
        return mark_safe(sanitize_rich_text(decoded_text))

    return mark_safe(linebreaks(decoded_text, autoescape=True))


register.filter('safe_gradient', safe_gradient)
register.filter('video_embed_url', video_embed_url)
