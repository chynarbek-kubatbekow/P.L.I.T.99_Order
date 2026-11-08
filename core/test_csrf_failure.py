import re
from urllib.parse import urlencode

from cryptography.fernet import Fernet
from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import Client, RequestFactory, SimpleTestCase, TestCase, override_settings

from .error_views import csrf_failure
from .feedback_security import feedback_cipher
from .models import PrivateFeedback


class CsrfFailureTests(SimpleTestCase):
    @override_settings(LOCAL_PREVIEW=True, DEBUG=False)
    def test_local_diagnostic_codes_never_echo_tokens_or_origins(self):
        cases = (
            ('CSRF cookie not set.', 'COOKIE_MISSING'),
            ('CSRF token missing.', 'TOKEN_MISSING'),
            ('Origin checking failed - https://PRIVATE_ORIGIN_CANARY', 'ORIGIN_MISMATCH'),
            ('Referer checking failed - PRIVATE_REFERER_CANARY', 'REFERER_MISMATCH'),
            ('CSRF token from POST incorrect.', 'TOKEN_MISMATCH'),
        )
        for reason, code in cases:
            request = RequestFactory().post('/admin/login/', {'csrfmiddlewaretoken': 'PRIVATE_TOKEN_CANARY'})
            response = csrf_failure(request, reason=reason)
            self.assertEqual(response.status_code, 403)
            self.assertContains(response, code, status_code=403)
            for marker in ('PRIVATE_ORIGIN_CANARY', 'PRIVATE_REFERER_CANARY', 'PRIVATE_TOKEN_CANARY', 'DEBUG=True'):
                self.assertNotContains(response, marker, status_code=403)
            self.assertIn('no-store', response['Cache-Control'])

    @override_settings(LOCAL_PREVIEW=False, DEBUG=False)
    def test_production_does_not_show_local_diagnostics(self):
        request = RequestFactory().post('/admin/login/')
        response = csrf_failure(request, reason='CSRF cookie not set.')
        self.assertEqual(response.status_code, 403)
        self.assertNotContains(response, 'COOKIE_MISSING', status_code=403)
        self.assertContains(response, '/admin/login/?fresh=1', status_code=403)


@override_settings(FEEDBACK_ENCRYPTION_KEYS=[Fernet.generate_key().decode()])
class FormReferrerPolicyTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.admin = get_user_model().objects.create_superuser('form-policy-admin', password='Synthetic-only-9#password')

    def check_forms(self, secure):
        client = Client(enforce_csrf_checks=True)
        origin = ('https' if secure else 'http') + '://testserver'

        def submit(source, target, values, expected=302):
            page = client.get(source, secure=secure)
            self.assertEqual(page.status_code, 200)
            policy = page['Referrer-Policy']
            token = re.search(rb'name="csrfmiddlewaretoken" value="([^"]+)"', page.content).group(1).decode()
            # Model a native HTML form's browser policy, rather than forcing a
            # correct Origin regardless of the server's broken response header.
            form_origin = 'null' if policy == 'no-referrer' else origin
            response = client.post(target, urlencode({**values, 'csrfmiddlewaretoken': token}),
                                   content_type='application/x-www-form-urlencoded', secure=secure,
                                   HTTP_ORIGIN=form_origin, HTTP_REFERER=origin + source)
            self.assertEqual(policy, 'same-origin')
            self.assertEqual(response.status_code, expected)
            return response

        submit('/admin/login/', '/admin/login/', {'username': 'form-policy-admin', 'password': 'Synthetic-only-9#password', 'next': '/admin/'})
        self.assertEqual(client.get('/admin/', secure=secure).status_code, 200)
        marker = 'Synthetic native form feedback <script>not executable</script>'
        submit('/contacts/', '/contacts/feedback/', {'message': marker})
        row = PrivateFeedback.objects.get()
        self.assertEqual(feedback_cipher().decrypt(row.encrypted_message.encode()).decode(), marker)
        response = client.get(f'/admin/core/privatefeedback/{row.pk}/change/', secure=secure)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '&lt;script&gt;')
        self.assertNotContains(response, '<script>not executable</script>')
        token = client.cookies[settings.CSRF_COOKIE_NAME].value
        for bad_origin in ('null', 'https://attacker.invalid'):
            response = client.post('/contacts/feedback/', urlencode({'message': marker, 'csrfmiddlewaretoken': token}),
                content_type='application/x-www-form-urlencoded', secure=secure, HTTP_ORIGIN=bad_origin)
            self.assertEqual(response.status_code, 403)
        self.assertEqual(PrivateFeedback.objects.count(), 1)

    @override_settings(LOCAL_PREVIEW=True, SECURE_SSL_REDIRECT=False, SESSION_COOKIE_SECURE=False, CSRF_COOKIE_SECURE=False)
    def test_local_http_login_feedback_and_admin_read_follow_form_policy(self):
        self.check_forms(False)

    @override_settings(LOCAL_PREVIEW=False, SECURE_SSL_REDIRECT=True, SESSION_COOKIE_SECURE=True, CSRF_COOKIE_SECURE=True)
    def test_production_https_login_feedback_and_admin_read_follow_form_policy(self):
        self.check_forms(True)
