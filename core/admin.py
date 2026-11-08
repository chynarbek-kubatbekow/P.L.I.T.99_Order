from django.contrib import admin

from .models import GalleryCategory, GalleryItem, News, NewsCategory, PrivateFeedback
from .feedback_security import feedback_cipher
from cryptography.fernet import InvalidToken
from django.core.exceptions import ImproperlyConfigured
from django.views.decorators.debug import sensitive_variables

admin.site.site_header = 'Управление сайтом лицея'
admin.site.site_title = 'Панель управления'
admin.site.index_title = 'Разделы'


admin.site.register(NewsCategory)
admin.site.register(News)
admin.site.register(GalleryCategory)
admin.site.register(GalleryItem)


@admin.register(PrivateFeedback)
class PrivateFeedbackAdmin(admin.ModelAdmin):
    list_display = ('id', 'created_at')
    readonly_fields = ('created_at', 'message')
    fields = readonly_fields
    actions = None

    @admin.display(description='Текст отзыва')
    @sensitive_variables()
    def message(self, obj):
        try:
            return feedback_cipher().decrypt(obj.encrypted_message.encode('ascii')).decode('utf-8')
        except (InvalidToken, ImproperlyConfigured, UnicodeError):
            return 'Не удалось расшифровать отзыв. Проверьте ключи шифрования.'

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
