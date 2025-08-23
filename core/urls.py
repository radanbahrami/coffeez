"""
Coffeez Project URL Configuration

Main URL configuration for the Coffeez Django project. This is the root
URL dispatcher that routes requests to the appropriate application URLs
and handles project-wide URL patterns.

The project uses a simple structure where most functionality is handled
by the 'coffeez' application, with Django admin available at /admin/.

Custom error handlers are configured for better user experience with
404 errors.

URL Structure:
- /admin/ - Django administrative interface
- / - All other URLs are handled by the coffeez application

For more information on Django URL configuration:
https://docs.djangoproject.com/en/5.2/topics/http/urls/
"""

from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    # Django admin interface for site administration
    path('admin/', admin.site.urls),
    
    # All application URLs are handled by the coffeez app
    path('', include('coffeez.urls')),
]

# Custom error handlers for better user experience
handler404 = 'coffeez.views.custom_page_not_found'
