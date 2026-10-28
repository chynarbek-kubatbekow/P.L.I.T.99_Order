import os

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.management.base import CommandError
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = 'Create a superuser from environment variables if it does not exist yet.'

    def handle(self, *args, **options):
        username = os.getenv('DJANGO_SUPERUSER_USERNAME', '').strip()
        email = os.getenv('DJANGO_SUPERUSER_EMAIL', '').strip()
        password = os.getenv('DJANGO_SUPERUSER_PASSWORD', '')

        if not username or not password:
            self.stdout.write('Admin env vars are not set. Skipping superuser creation.')
            return

        User = get_user_model()

        if User.objects.filter(username=username).exists():
            self.stdout.write(f'Superuser "{username}" already exists. Skipping.')
            return

        candidate = User(username=username, email=email, is_staff=True, is_superuser=True)
        try:
            validate_password(password, user=candidate)
        except ValidationError:
            raise CommandError('Admin password does not satisfy password policy.') from None

        User.objects.create_superuser(
            username=username,
            email=email,
            password=password,
        )
        self.stdout.write(self.style.SUCCESS(f'Superuser "{username}" created successfully.'))
