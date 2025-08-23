"""
Coffeez URL Configuration

This module defines URL patterns for the Coffeez application, mapping
URL paths to their corresponding view functions. The URL structure
supports creator profiles, donations, authentication, and administrative
functions.

URL Pattern Organization:
- Root and static pages (index, about, contact, etc.)
- Authentication flows (login, logout, email verification)
- Creator-specific functionality (profiles, dashboard, donations)
- Administrative and guide pages
- Dynamic creator profile URLs (must be last due to catch-all pattern)
"""

from . import views
from django.urls import path, include
from django.contrib.auth import views as auth_views

urlpatterns = [
    # Main application pages
    path('', views.index, name='index'),
    path('about/', views.about, name='about'),
    path('contact/', views.contact, name='contact'),
    path('terms/', views.terms, name='terms'),
    path('privacy/', views.privacy, name='privacy'),
    path('branding/', views.branding, name='branding'),
    
    # Authentication and account management
    path('accounts/login/', views.login_page, name='account_login'),
    path('accounts/logout/', auth_views.LogoutView.as_view(next_page='/'), name='account_logout'),
    path('accounts/signup/', views.redirect_signup, name='account_signup'),
    # Include django-allauth URLs for social authentication (Google OAuth)
    path('accounts/', include('allauth.socialaccount.urls')),
    path('accounts/', include('allauth.socialaccount.providers.google.urls')),
    
    # Email verification and account setup
    path('verify-email/', views.verify_email, name='verify_email'),
    path('finish-setup/', views.finish_setup, name='finish_setup'),
    path('email-login/', views.email_login, name='email_login'),
    
    # Creator management and discovery
    path('creators/', views.creator_list, name='creator_list'),
    path('dashboard/', views.creator_dashboard, name='creator_dashboard'),
    path('dashboard/update-profile-picture/', views.update_profile_picture, name='update_profile_picture'),
    path('dashboard/remove-profile-picture/', views.remove_profile_picture, name='remove_profile_picture'),
    path('dashboard/deactivate-account/', views.deactivate_account, name='deactivate_account'),
    path('update-profile/', views.update_profile, name='update_profile'),
    
    # Donation and payment flows
    path('creator/<int:creator_id>/donation/', views.show_wallet, name='show_wallet'),
    path('donation/<int:purchase_id>/', views.show_wallet, name='show_wallet_existing'),
    path('donation/check/<int:purchase_id>/', views.check_donation, name='check_donation'),
    
    # File serving and media
    path('media/<path:filename>/', views.serve_secure_file, name='serve_secure_file'),
    
    # Guide and documentation pages
    path('guides/', views.guides, name='guides'),
    path('guides/accessing-funds/', views.accessing_funds, name='accessing_funds'),
    path('guides/supporting/', views.supporting, name='supporting'),
    path('guides/moving-funds/', views.moving_funds, name='moving_funds'),
    
    # Dynamic creator profile URLs (MUST be last due to catch-all pattern)
    path('<str:username>/', views.creator_profile, name='creator_profile'),
]
