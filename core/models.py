from django.db import models
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.utils.text import slugify
import uuid

from .media_utils import (
    gallery_image_upload_to,
    news_cover_upload_to,
    optimize_uploaded_image,
    validate_uploaded_image,
)
from .content_security import sanitize_rich_text, validate_gradient, validate_video_url


class NewsCategory(models.Model):
    name = models.CharField('Название', max_length=100)
    slug = models.SlugField('Slug', unique=True)
    color = models.CharField('Цвет (CSS класс)', max_length=50, default='badge-gray')

    class Meta:
        verbose_name = 'Категория новостей'
        verbose_name_plural = 'Категории новостей'
        ordering = ['name']

    def __str__(self):
        return self.name


class News(models.Model):
    title        = models.CharField('Заголовок', max_length=300)
    slug         = models.SlugField('Slug', unique=True, blank=True, max_length=320)
    excerpt      = models.TextField('Краткое описание', max_length=400)
    content      = models.TextField('Полный текст')
    cover_image  = models.ImageField(
        'Обложка',
        upload_to=news_cover_upload_to,
        blank=True,
        null=True,
    )
    cover_emoji  = models.CharField('Эмодзи обложки', max_length=10, default='📰')
    cover_gradient = models.CharField(
        'Градиент обложки', max_length=120,
        default='linear-gradient(135deg,#0D3060,#1668C0)'
    )
    category     = models.ForeignKey(
        NewsCategory, on_delete=models.SET_NULL,
        null=True, blank=True, verbose_name='Категория', related_name='news'
    )
    is_featured  = models.BooleanField('Главная новость', default=False)
    is_published = models.BooleanField('Опубликована', default=True)
    published_at = models.DateTimeField('Дата публикации', default=timezone.now)
    created_at   = models.DateTimeField('Создана', auto_now_add=True)
    updated_at   = models.DateTimeField('Обновлена', auto_now=True)

    class Meta:
        verbose_name = 'Новость'
        verbose_name_plural = 'Новости'
        ordering = ['-published_at']

    def __str__(self):
        return self.title

    def clean(self):
        super().clean()
        try:
            validate_gradient(self.cover_gradient)
        except ValidationError as exc:
            raise ValidationError({'cover_gradient': exc.messages}) from exc
        if len(self.content) > 100_000:
            raise ValidationError({'content': 'Текст новости не должен превышать 100 000 символов.'})
        try:
            validate_uploaded_image(self.cover_image)
        except ValidationError as exc:
            raise ValidationError({'cover_image': exc.messages}) from exc

    def save(self, *args, **kwargs):
        validate_gradient(self.cover_gradient)
        self.content = sanitize_rich_text(self.content) if '<' in self.content or '&' in self.content else self.content
        optimized_cover = optimize_uploaded_image(self.cover_image)
        if optimized_cover is not None:
            self.cover_image = optimized_cover

        if not self.slug:
            base = slugify(self.title, allow_unicode=False)[:310]
            self.slug = base if base else str(uuid.uuid4())[:8]
        self.full_clean()
        super().save(*args, **kwargs)

    def get_absolute_url(self):
        from django.urls import reverse
        return reverse('news_detail', kwargs={'slug': self.slug})


class GalleryCategory(models.Model):
    name  = models.CharField('Название', max_length=100)
    slug  = models.SlugField('Slug', unique=True)
    order = models.PositiveIntegerField('Порядок', default=0)

    class Meta:
        verbose_name = 'Категория галереи'
        verbose_name_plural = 'Категории галереи'
        ordering = ['order', 'name']

    def __str__(self):
        return self.name


class GalleryItem(models.Model):
    MEDIA_CHOICES = [('photo', 'Фотография'), ('video', 'Видео (ссылка)')]

    title      = models.CharField('Подпись', max_length=200, blank=True)
    media_type = models.CharField('Тип', max_length=10, choices=MEDIA_CHOICES, default='photo')
    image      = models.ImageField(
        'Фото',
        upload_to=gallery_image_upload_to,
        blank=True,
        null=True,
    )
    video_url  = models.URLField('Ссылка на видео', blank=True)
    category   = models.ForeignKey(
        GalleryCategory, on_delete=models.SET_NULL,
        null=True, blank=True, verbose_name='Категория', related_name='items'
    )
    is_published = models.BooleanField('Опубликовано', default=True)
    order        = models.PositiveIntegerField('Порядок', default=0)
    created_at   = models.DateTimeField('Добавлено', auto_now_add=True)

    class Meta:
        verbose_name = 'Элемент галереи'
        verbose_name_plural = 'Галерея'
        ordering = ['order', '-created_at']

    def __str__(self):
        return self.title or f'Медиа #{self.pk}'

    def clean(self):
        super().clean()
        validate_video_url(self.video_url)
        try:
            validate_uploaded_image(self.image)
        except ValidationError as exc:
            raise ValidationError({'image': exc.messages}) from exc

        if self.media_type == 'photo':
            if not self.image:
                raise ValidationError({'image': 'Для фото нужно загрузить изображение.'})
            self.video_url = ''

        if self.media_type == 'video':
            if not self.video_url:
                raise ValidationError({'video_url': 'Для видео нужно указать ссылку.'})
            self.image = None

    def save(self, *args, **kwargs):
        optimized_image = optimize_uploaded_image(self.image)
        if optimized_image is not None:
            self.image = optimized_image

        self.full_clean()
        super().save(*args, **kwargs)


class AdminLoginThrottle(models.Model):
    # Only keyed hashes of IP/account names are stored, never credentials.
    key = models.CharField(max_length=64, primary_key=True)
    expires_at = models.DateTimeField(db_index=True)
    attempts = models.PositiveIntegerField(default=0)
