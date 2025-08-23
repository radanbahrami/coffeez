"""
Django Settings for Coffeez Project

Configuration file for the Coffeez application, a platform for creators
to receive cryptocurrency donations through virtual "coffee" purchases.

Key Features Configured:
- Google OAuth integration via django-allauth
- MySQL database support with PyMySQL
- Email verification system
- hCaptcha bot protection
- File upload handling for creator profiles
- Security settings for production deployment

Environment Variables Required:
- DJANGO_SECRET_KEY: Django secret key for cryptographic signing
- HCAPTCHA_SECRET: Secret key for hCaptcha verification
- MYSQL_* variables: Database connection parameters
- EMAIL_* variables: Email backend configuration (optional)

For more information on Django settings:
https://docs.djangoproject.com/en/5.2/topics/settings/
"""

import os
from pathlib import Path
from dotenv import load_dotenv
import pymysql

# Configure PyMySQL to work as MySQLdb replacement
pymysql.install_as_MySQLdb()

# Build paths inside the project
BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment variables from .env file
load_dotenv()

# Security Settings
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')
HCAPTCHA_SECRET_KEY = os.environ.get('HCAPTCHA_SECRET')

# SECURITY WARNING: Don't run with debug turned on in production!
DEBUG = os.getenv("DJANGO_DEBUG", "False") == "True"

ALLOWED_HOSTS = []

# Application Definition
INSTALLED_APPS = [
    # Default Django applications
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # Coffeez main application
    'coffeez',

    # Django Allauth applications for social authentication
    'django.contrib.sites',  # Required by django-allauth
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    'allauth.socialaccount.providers.google',  # Google OAuth provider
]

# Site ID required by django-allauth
SITE_ID = 2

# Authentication Backends
AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',  # Default Django authentication
    'allauth.account.auth_backends.AuthenticationBackend',  # Allauth social authentication
]

# URL Redirects Configuration
LOGIN_URL = '/accounts/login/'  # Custom login page
LOGIN_REDIRECT_URL = '/finish-setup/'  # Post-login profile setup
LOGOUT_REDIRECT_URL = '/'  # Homepage after logout

# Django Allauth Configuration
# Restricts to social authentication (Google) only, disabling traditional signup
SOCIALACCOUNT_ADAPTER = 'coffeez.adapters.CustomSocialAccountAdapter'
SOCIALACCOUNT_LOGIN_ON_GET = True  # Allow login on GET request
ACCOUNT_SIGNUP_ENABLED = False  # Disable allauth's email/password signup
ACCOUNT_EMAIL_VERIFICATION = 'none'  # Custom email verification system
ACCOUNT_RATE_LIMITS = {
    'login_failed': None,  # Disable rate limiting for failed logins
}

# Google OAuth Provider Configuration
SOCIALACCOUNT_PROVIDERS = {
    'google': {
        'SCOPE': [
            'email',  # Request email address from Google
        ],
        'AUTH_PARAMS': {
            'access_type': 'online',  # Don't request offline access
        }
    }
}


MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'allauth.account.middleware.AccountMiddleware',
]

ROOT_URLCONF = 'core.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'core.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': os.environ.get('MYSQL_DATABASE', 'your_db_name'),
        'USER': os.environ.get('MYSQL_USER', 'your_db_user'),
        'PASSWORD': os.environ.get('MYSQL_PASSWORD', 'your_db_password'),
        'HOST': os.environ.get('MYSQL_HOST', 'localhost'),
        'PORT': os.environ.get('MYSQL_PORT', '3306'),
    }
}

# Password validation
# https://docs.djangoproject.com/en/5.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.2/howto/static-files/

STATIC_URL = 'static/'

# Default primary key field type
# https://docs.djangoproject.com/en/5.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MEDIA_ROOT = os.path.join(BASE_DIR, '../media')  # Directory outside web root
MEDIA_URL = '/media/'  # Logical URL for media files

# Email settings (development defaults; override via environment in production)
EMAIL_BACKEND = os.environ.get('EMAIL_BACKEND', 'django.core.mail.backends.console.EmailBackend')
EMAIL_HOST = os.environ.get('EMAIL_HOST', '')
EMAIL_PORT = int(os.environ.get('EMAIL_PORT', '0') or 0)
EMAIL_HOST_USER = os.environ.get('EMAIL_HOST_USER', '')
EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_HOST_PASSWORD', '')
EMAIL_USE_TLS = os.environ.get('EMAIL_USE_TLS', 'True') == 'True'
EMAIL_USE_SSL = os.environ.get('EMAIL_USE_SSL', 'False') == 'False' and False  # prefer TLS
DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL', 'no-reply@coffeez.local')
