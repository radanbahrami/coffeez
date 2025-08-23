"""
Coffeez Django Application Configuration

This module contains the Django application configuration for the Coffeez app.
Sets up the application metadata and default field types for the project.
"""

from django.apps import AppConfig


class CoffeezConfig(AppConfig):
    """
    Configuration class for the Coffeez Django application.
    
    Defines basic application settings including the default auto field
    type for model primary keys and the application name.
    
    Attributes:
        default_auto_field: Specifies BigAutoField for auto-generated primary keys
        name: The Python module name for this Django application
    """
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'coffeez'
