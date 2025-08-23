"""
Coffeez Models

This module contains the core data models for the Coffeez application:
- Creator: Represents content creators who can receive coffee donations
- CoffeePurchase: Represents coffee purchases/donations from supporters
- EmailVerification: Tracks email verification status for users
- EmailVerificationCode: Manages time-bound verification codes

The models handle profile management, donation tracking, and user verification.
"""

from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone
from datetime import timedelta
from django.urls import reverse
from PIL import Image
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.core.validators import FileExtensionValidator
from .validators import validate_file_size, validate_username
import os
import re


class Creator(models.Model):
    """
    Represents a content creator who can receive coffee donations.
    
    Each Creator is linked to a Django User account and contains additional
    profile information including display settings, wallet details, and
    verification status. The model handles profile picture processing,
    file sanitization, and metadata removal for security.
    
    Attributes:
        user: One-to-one relationship with Django User model
        username: Unique username for the creator profile (validated)
        display_name: Public display name shown to supporters
        profile_picture: Optional profile image (validated and processed)
        bio: Optional biography text
        wallet_address: TRX wallet address for receiving donations
        email: Email address (may differ from User.email)
        verified: Whether the creator is verified by platform
        suspended: Whether the creator account is suspended
        deactivated: Whether the creator has deactivated their account
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    username = models.CharField(max_length=30, unique=True, validators=[validate_username])
    display_name = models.CharField(max_length=100)
    profile_picture = models.ImageField(
        upload_to='creator_pics/',
        blank=True,
        null=True,
        validators=[
            FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png']),
            validate_file_size
        ]
    )
    bio = models.TextField(blank=True)
    wallet_address = models.CharField(max_length=255, blank=True, null=True)
    email = models.EmailField(blank=True, null=True)
    verified = models.BooleanField(default=False)  # <-- Add this line
    suspended = models.BooleanField(default=False)
    deactivated = models.BooleanField(default=False)

    def __str__(self):
        """Return the display name as string representation."""
        return self.display_name

    def get_profile_picture_url(self):
        """
        Get the secure URL for the creator's profile picture.
        
        Returns:
            str: URL to the profile picture via secure file serving, or None if no picture
        """
        if self.profile_picture:
            # Include the correct subdirectory
            return reverse('serve_secure_file', args=[f"creator_pics/{os.path.basename(self.profile_picture.name)}"])
        return None

    def save(self, *args, **kwargs):
        """
        Custom save method that handles profile picture processing.
        
        Performs the following operations on profile pictures:
        1. Sanitizes the filename to prevent security issues
        2. Removes metadata from images for privacy
        3. Renames files if necessary to ensure safe filenames
        
        Raises:
            ValueError: If file processing fails
        """
        # Call the parent save method
        super().save(*args, **kwargs)

        if self.profile_picture:
            try:
                # Sanitize file name
                sanitized_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', os.path.basename(self.profile_picture.name))
                sanitized_path = os.path.join(os.path.dirname(self.profile_picture.path), sanitized_name)

                # Rename the file if necessary
                if self.profile_picture.path != sanitized_path:
                    # Check if the file exists
                    if not os.path.exists(self.profile_picture.path):
                        raise ValueError(f"File does not exist: {self.profile_picture.path}")

                    # Read the file content
                    with open(self.profile_picture.path, 'rb') as f:
                        file_content = f.read()

                    # Save the file with the sanitized name
                    new_file_path = default_storage.save(sanitized_path, ContentFile(file_content))

                    # Delete the old file
                    default_storage.delete(self.profile_picture.path)

                    # Update the name in the database
                    self.profile_picture.name = os.path.join('creator_pics/', sanitized_name)
                    super().save(update_fields=['profile_picture'])  # Save the updated name
                    print("Renaming successful")

                # Remove metadata
                try:
                    img = Image.open(self.profile_picture.path)
                    img_without_metadata = Image.new(img.mode, img.size)
                    img_without_metadata.putdata(list(img.getdata()))
                    img_without_metadata.save(self.profile_picture.path)
                except Exception as e:
                    raise ValueError(f"Error stripping metadata: {e}")

            except Exception as e:
                raise ValueError(f"Error in save method: {e}")


class CoffeePurchase(models.Model):
    """
    Represents a coffee purchase/donation from a supporter to a creator.
    
    Tracks the complete donation flow including buyer information, payment details,
    and transaction status. Each purchase represents one or more virtual "coffees"
    being bought for a creator, with cryptocurrency payment tracking.
    
    Attributes:
        buyer_name: Name of the person making the donation
        buyer_message: Optional message from buyer to creator
        creator: The creator receiving the donation
        creator_wallet_address: Snapshot of creator's wallet at purchase time
        amount: Exact cryptocurrency amount to be paid
        coffee_qty: Number of virtual coffees being purchased
        crypto_type: Type of cryptocurrency (typically TRX)
        transaction_id: Unique identifier for tracking payment
        timestamp: When the purchase was created (deprecated, use created_at)
        status: Current status (pending/completed/expired)
        created_at: When the purchase was created
    """
    PURCHASE_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('completed', 'Completed'),
        ('expired', 'Expired'),
    ]
    
    buyer_name = models.CharField(max_length=100)
    buyer_message = models.TextField(blank=True, null=True)
    creator = models.ForeignKey(Creator, on_delete=models.CASCADE)
    creator_wallet_address = models.CharField(max_length=255, blank=True, null=True)
    amount = models.DecimalField(max_digits=10, decimal_places=6)
    coffee_qty = models.IntegerField(default=1)
    crypto_type = models.CharField(max_length=50)
    transaction_id = models.CharField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=PURCHASE_STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        """Return a human-readable description of the purchase."""
        return f"{self.buyer_name} bought {self.coffee_qty} coffee(s) for {self.creator}"
    
    def is_expired(self):
        """
        Check if this purchase has expired.
        
        Purchases expire after 30 minutes if they remain in pending status.
        This prevents indefinite pending transactions.
        
        Returns:
            bool: True if the purchase is expired, False otherwise
        """
        if self.status != 'pending':
            return False
        return timezone.now() - self.created_at > timedelta(minutes=30)


class EmailVerification(models.Model):
    """
    Tracks email verification status for users.
    
    This model maintains a record of whether each user has verified their
    email address. Email verification is required for certain platform
    features and security purposes.
    
    Attributes:
        user: One-to-one relationship with Django User
        is_verified: Whether the user's email has been verified
        created_at: When the verification record was created
        updated_at: When the verification status was last updated
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='email_verification')
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        """Return a human-readable description of the verification status."""
        status = 'verified' if self.is_verified else 'unverified'
        return f"EmailVerification({self.user.email}, {status})"


class EmailVerificationCode(models.Model):
    """
    Time-bound one-time verification codes for email verification.
    
    Generates and manages temporary codes sent to users for email verification.
    Codes have expiration times and can only be used once to prevent abuse.
    Database indexes are optimized for lookup performance.
    
    Attributes:
        user: The user this verification code belongs to
        code: The 6-character verification code
        created_at: When the code was generated
        expires_at: When the code expires
        used: Whether the code has been used already
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='verification_codes')
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)

    class Meta:
        """Database optimization settings for EmailVerificationCode."""
        indexes = [
            # Optimize lookups for verification attempts
            models.Index(fields=['user', 'code', 'used']),
            # Optimize cleanup of expired codes
            models.Index(fields=['expires_at']),
        ]

    def __str__(self):
        """Return a secure string representation (code is masked for security)."""
        return f"Code(***) for {self.user.email} (used={self.used})"

    def is_expired(self):
        """
        Check if this verification code has expired.
        
        Returns:
            bool: True if the code is past its expiration time
        """
        return timezone.now() >= self.expires_at
