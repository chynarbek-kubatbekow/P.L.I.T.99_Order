from django.conf import settings
from django.shortcuts import render
from django.views.decorators.cache import never_cache
from django.views.decorators.debug import sensitive_post_parameters, sensitive_variables


@never_cache
@sensitive_post_parameters()
@sensitive_variables()
def csrf_failure(request, reason=''):
    # Never echo Django's raw reason: it can include a user-controlled origin.
    if reason == 'CSRF cookie not set.':
        code, hint = 'COOKIE_MISSING', 'Браузер не передал cookie формы. Разрешите cookies для 127.0.0.1 и откройте форму заново.'
    elif reason == 'CSRF token missing.':
        code, hint = 'TOKEN_MISSING', 'В отправленной форме нет защитного поля. Откройте страницу входа заново; не отправляйте сохранённую старую форму.'
    elif reason.startswith('Origin checking failed'):
        code, hint = 'ORIGIN_MISMATCH', 'Адрес отправки не совпал с разрешённым адресом сайта. Откройте вход напрямую, без предпросмотра и подмены адреса расширениями.'
    elif reason.startswith('Referer checking failed'):
        code, hint = 'REFERER_MISMATCH', 'Браузер не передал допустимый адрес исходной страницы. Проверьте расширения, меняющие заголовки запросов.'
    else:
        code, hint = 'TOKEN_MISMATCH', 'Cookie и защитное поле формы не совпали. Такое бывает со старой вкладкой или после входа в другой вкладке.'
    return render(request, '403_csrf.html', {
        'local_preview': settings.LOCAL_PREVIEW,
        'csrf_code': code,
        'csrf_hint': hint,
        'retry_url': '/admin/login/?fresh=1' if request.path.startswith('/admin/') else '/contacts/',
    }, status=403)
