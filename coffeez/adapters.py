"""
Coffeez Social Authentication Adapters

This module customizes django-allauth behavior for social authentication,
specifically for Google OAuth integration. It handles user creation,
profile setup, and post-authentication flow customization.

The adapter ensures proper integration between social login and the
Coffeez creator profile system.
"""

from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from django.shortcuts import redirect
from django.contrib.auth import login
from .models import Creator


class CustomSocialAccountAdapter(DefaultSocialAccountAdapter):
    """
    Custom adapter for social account authentication (Google OAuth).
    
    Overrides default django-allauth behavior to integrate with Coffeez
    workflow. Handles automatic user creation, profile linking, and
    redirects users to appropriate setup pages after authentication.
    """
    
    def pre_social_login(self, request, sociallogin):
        """
        Handle pre-login processing for social authentication.
        
        Automatically logs in existing users and prepares the state
        for new user creation.
        
        Args:
            request: HTTP request object
            sociallogin: SocialLogin instance from django-allauth
        """
        # If user already exists, log them in immediately
        if sociallogin.is_existing:
            login(request, sociallogin.user, backend='django.contrib.auth.backends.ModelBackend')
        else:
            # For new users, set process state to login for automatic creation
            sociallogin.state['process'] = 'login'

    def is_auto_signup_allowed(self, request, sociallogin):
        """
        Control whether automatic user signup is allowed.
        
        Returns True to allow automatic user creation without manual
        signup forms, streamlining the Google OAuth flow.
        
        Args:
            request: HTTP request object
            sociallogin: SocialLogin instance from django-allauth
            
        Returns:
            bool: Always True to enable automatic signup
        """
        return True  # Allow automatic user creation

    def get_login_redirect_url(self, request):
        """
        Determine where to redirect users after successful social login.
        
        All users (new and existing) are redirected to the setup page
        to complete their creator profile configuration.
        
        Args:
            request: HTTP request object
            
        Returns:
            str: URL path for post-login redirect
        """
        return '/finish-setup/'  # Redirect to profile setup after Google authentication

    def save_user(self, request, sociallogin, form=None):
        """
        Custom user saving logic for social authentication.
        
        Extracts email from Google OAuth data and ensures it's properly
        stored in both the User model and the Creator profile. This
        maintains data consistency across the platform.
        
        Args:
            request: HTTP request object
            sociallogin: SocialLogin instance containing OAuth data
            form: Optional form data (not used in this flow)
            
        Returns:
            User: The created or updated User instance
        """
        user = super().save_user(request, sociallogin, form)
        
        # Extract email from Google OAuth response
        email = sociallogin.account.extra_data.get('email')
        print("Email from Google:", email)
        
        if email:
            # Update User model with email from Google
            user.email = email
            user.save()
            
            # Create or update Creator profile with email
            # This ensures the Creator profile has the correct email
            Creator.objects.update_or_create(
                user=user,
                defaults={'email': email}
            )
        
        return user