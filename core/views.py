import logging

from django.db import DatabaseError
from django.views.decorators.http import require_safe
from django.http import Http404, JsonResponse
from django.shortcuts import get_object_or_404, render

from .models import GalleryCategory, GalleryItem, News, NewsCategory

logger = logging.getLogger(__name__)


def safe_first(queryset, context):
    try:
        return queryset.first()
    except DatabaseError as exc:
        logger.warning('Database is not ready while loading %s', context)
        return None


def safe_list(queryset, context):
    try:
        return list(queryset)
    except DatabaseError as exc:
        logger.warning('Database is not ready while loading %s', context)
        return []


def safe_get_or_404(queryset, context, **kwargs):
    try:
        return get_object_or_404(queryset, **kwargs)
    except DatabaseError as exc:
        logger.warning('Database is not ready while loading %s', context)
        raise Http404('Content is temporarily unavailable.') from exc


@require_safe
def index(request):
    featured_news = safe_first(
        News.objects.filter(is_published=True, is_featured=True),
        'featured news for index',
    )
    latest_news = safe_list(
        News.objects.filter(is_published=True).exclude(
            pk=featured_news.pk if featured_news else 0
        )[:3],
        'latest news for index',
    )

    return render(
        request,
        'core/index.html',
        {
            'featured_news': featured_news,
            'latest_news': latest_news,
        },
    )


@require_safe
def about(request):
    return render(request, 'core/about.html')


@require_safe
def education(request):
    return render(request, 'core/education.html')


@require_safe
def results(request):
    return render(request, 'core/results.html')


@require_safe
def admission(request):
    return render(request, 'core/admission.html')


@require_safe
def media_hub(request):
    view_mode = request.GET.get('view', 'all')
    if view_mode not in {'all', 'news', 'gallery'}:
        view_mode = 'all'

    news_categories = safe_list(NewsCategory.objects.all(), 'news categories')
    gallery_categories = safe_list(GalleryCategory.objects.all(), 'gallery categories')

    active_news_cat = None
    news_qs = News.objects.filter(is_published=True)
    news_cat_slug = request.GET.get('news_cat')
    if news_cat_slug:
        active_news_cat = safe_get_or_404(
            NewsCategory.objects.all(),
            'active news category',
            slug=news_cat_slug,
        )
        news_qs = news_qs.filter(category=active_news_cat)

    featured = safe_first(news_qs.filter(is_featured=True), 'featured media news')
    news_list = safe_list(
        news_qs.exclude(pk=featured.pk if featured else 0),
        'media hub news list',
    )

    active_gallery_cat = None
    gallery_qs = GalleryItem.objects.filter(is_published=True)
    gallery_cat_slug = request.GET.get('gallery_cat')
    if gallery_cat_slug:
        active_gallery_cat = safe_get_or_404(
            GalleryCategory.objects.all(),
            'active gallery category',
            slug=gallery_cat_slug,
        )
        gallery_qs = gallery_qs.filter(category=active_gallery_cat)
    gallery_items = safe_list(gallery_qs, 'media hub gallery items')

    return render(
        request,
        'core/media_hub.html',
        {
            'view_mode': view_mode,
            'news_categories': news_categories,
            'gallery_categories': gallery_categories,
            'active_news_cat': active_news_cat,
            'active_gallery_cat': active_gallery_cat,
            'featured': featured,
            'news_list': news_list,
            'gallery_items': gallery_items,
        },
    )


@require_safe
def news_list(request):
    category_slug = request.GET.get('cat')
    categories = safe_list(NewsCategory.objects.all(), 'news categories')
    active_cat = None
    news_qs = News.objects.filter(is_published=True)

    if category_slug:
        active_cat = safe_get_or_404(
            NewsCategory.objects.all(),
            'active news category',
            slug=category_slug,
        )
        news_qs = news_qs.filter(category=active_cat)

    featured = safe_first(news_qs.filter(is_featured=True), 'featured news list item')
    news_qs = safe_list(
        news_qs.exclude(pk=featured.pk if featured else 0),
        'news list items',
    )

    return render(
        request,
        'core/news.html',
        {
            'news_list': news_qs,
            'featured': featured,
            'categories': categories,
            'active_cat': active_cat,
        },
    )


@require_safe
def news_detail(request, slug):
    news = safe_get_or_404(
        News.objects.filter(is_published=True),
        'news detail',
        slug=slug,
    )
    related = safe_list(
        News.objects.filter(is_published=True).exclude(pk=news.pk)[:3],
        'related news',
    )
    return render(request, 'core/news_detail.html', {'news': news, 'related': related})


@require_safe
def gallery(request):
    category_slug = request.GET.get('cat')
    categories = safe_list(GalleryCategory.objects.all(), 'gallery categories')
    active_cat = None
    items_qs = GalleryItem.objects.filter(is_published=True)

    if category_slug:
        active_cat = safe_get_or_404(
            GalleryCategory.objects.all(),
            'active gallery category',
            slug=category_slug,
        )
        items_qs = items_qs.filter(category=active_cat)
    items_qs = safe_list(items_qs, 'gallery items')

    return render(
        request,
        'core/gallery.html',
        {
            'items': items_qs,
            'categories': categories,
            'active_cat': active_cat,
        },
    )


@require_safe
def contacts(request):
    return render(request, 'core/contacts.html')


@require_safe
def healthz(request):
    return JsonResponse({'status': 'ok'})
