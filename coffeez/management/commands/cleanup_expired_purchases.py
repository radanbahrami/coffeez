"""
Coffeez Cleanup Expired Purchases Management Command

This Django management command cleans up expired pending coffee purchases
that were never completed. Purchases expire after 30 minutes if no payment
is detected on the blockchain.

Regular cleanup prevents database bloat and maintains data hygiene.
Should be run periodically via cron job or similar scheduling system.

Usage:
    python manage.py cleanup_expired_purchases
"""

from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from coffeez.models import CoffeePurchase


class Command(BaseCommand):
    """
    Django management command to clean up expired pending purchases.
    
    Automatically removes coffee purchases that have been pending for more
    than 30 minutes without payment confirmation from the blockchain.
    This prevents accumulation of stale transaction records.
    """
    help = 'Clean up expired pending purchases (older than 30 minutes)'

    def handle(self, *args, **options):
        """
        Execute the cleanup operation.
        
        Finds and deletes all pending purchases that are older than 30 minutes.
        Provides feedback on the number of records cleaned up.
        
        Args:
            *args: Positional arguments (unused)
            **options: Command options (unused)
        """
        # Calculate cutoff time (30 minutes ago)
        cutoff_time = timezone.now() - timedelta(minutes=30)
        
        # Find expired pending purchases
        expired_purchases = CoffeePurchase.objects.filter(
            status='pending',
            created_at__lt=cutoff_time
        )
        
        # Count and delete expired purchases
        count = expired_purchases.count()
        expired_purchases.delete()
        
        # Provide success feedback
        self.stdout.write(
            self.style.SUCCESS(
                f'Successfully deleted {count} expired pending purchases'
            )
        )