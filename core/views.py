import logging
import secrets
import time

from django.db import DatabaseError
from django.views.decorators.http import require_safe
from django.http import Http404, JsonResponse
from django.shortcuts import get_object_or_404, render

from .models import GalleryCategory, GalleryItem, News, NewsCategory
from django.core.exceptions import ImproperlyConfigured, RequestDataTooBig
from django.db import connection, OperationalError, transaction
from django.http import HttpResponse, HttpResponseRedirect
from django.urls import reverse
from django.views.decorators.cache import never_cache
from django.views.decorators.debug import sensitive_post_parameters, sensitive_variables
from django.views.decorators.http import require_POST
from .forms import FeedbackForm
from .feedback_security import feedback_cipher, take_feedback_quota
from .models import PrivateFeedback

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
@never_cache
def contacts(request):
    return render(request, 'core/contacts.html', {'feedback_form': FeedbackForm(), 'feedback_sent': request.GET.get('sent') == '1'})


@require_POST
@never_cache
@sensitive_post_parameters()
@sensitive_variables()
def submit_feedback(request):
    if request.content_type != 'application/x-www-form-urlencoded':
        return HttpResponse('Неподдерживаемый формат.', status=415)
    try:
        if len(request.body) > 65_536:
            return HttpResponse('Сообщение слишком большое.', status=413)
        allowed = {'message', 'website', 'csrfmiddlewaretoken'}
        if any(key not in allowed or len(request.POST.getlist(key)) != 1 for key in request.POST):
            return HttpResponse('Некорректные поля формы.', status=400)
        form = FeedbackForm(request.POST)
    except RequestDataTooBig:
        return HttpResponse('Сообщение слишком большое.', status=413)
    if not form.is_valid():
        # Never reflect private submissions in an error page or browser cache.
        return render(request, 'core/contacts.html', {'feedback_form': FeedbackForm(),
                      'feedback_error': 'Введите от 10 до 4000 символов без управляющих знаков.'}, status=400)
    if form.cleaned_data['website']:
        return HttpResponseRedirect(reverse('contacts') + '?sent=1#feedback')
    try:
        cipher = feedback_cipher()
        encrypted = cipher.encrypt(form.cleaned_data['message'].encode('utf-8')).decode('ascii')
        if not store_feedback(encrypted, request.META.get('REMOTE_ADDR', '')):
            response = HttpResponse('Слишком много сообщений. Попробуйте через 10 минут.', status=429)
            response['Retry-After'] = '600'
            return response
    except (DatabaseError, ImproperlyConfigured):
        return HttpResponse('Ящик временно недоступен. Попробуйте позже.', status=503)
    return HttpResponseRedirect(reverse('contacts') + '?sent=1#feedback')


@sensitive_variables()
def store_feedback(encrypted_message, ip):
    # Quota and insert commit together. Only a known rolled-back SQLite
    # BUSY/LOCKED transaction is retried, never an arbitrary/unknown DB failure.
    for attempt in range(4):
        try:
            with transaction.atomic():
                if not take_feedback_quota(ip):
                    return False
                PrivateFeedback.objects.create(encrypted_message=encrypted_message)
            return True
        except OperationalError as exc:
            code = getattr(exc.__cause__, 'sqlite_errorcode', None)
            if connection.vendor != 'sqlite' or code is None or code & 255 not in {5, 6} or attempt == 3:
                raise
            time.sleep(0.01 * (2 ** attempt) + secrets.randbelow(10) / 1000)


@require_safe
def healthz(request):
    return JsonResponse({'status': 'ok'})
