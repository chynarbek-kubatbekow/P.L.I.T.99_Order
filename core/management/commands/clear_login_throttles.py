from django.core.management.base import BaseCommand
from django.utils import timezone

from core.models import AdminLoginThrottle


class Command(BaseCommand):
    help = 'Delete expired admin login throttle buckets (schedule daily).'

    def handle(self, *args, **options):
        deleted, _ = AdminLoginThrottle.objects.filter(expires_at__lt=timezone.now()).delete()
        self.stdout.write(f'Deleted expired throttle rows: {deleted}')
