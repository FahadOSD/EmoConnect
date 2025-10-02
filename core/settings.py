from datetime import timedelta
from pathlib import Path

from decouple import config

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = config(
    "SECRET_KEY",
    cast=str,
    default="django-insecure-02vma=vnba#kgb*m6t7pxm$@rt!8tykl9ggqdm+n7%vnnca1!b",
)

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = config("DEBUG", cast=bool, default=True)

ALLOWED_HOSTS = ["*"]


# Application definition

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
]


EXTERNAL_APPS = [
    "rest_framework",
    "rest_framework.authtoken",
    "django_filters",
    "corsheaders",
    "drf_spectacular",
    'drf_yasg', # Swagger 
    # social auth
    "django.contrib.sites",
    "allauth",  # django-allauth for social login
    "allauth.account",  # Email-based authentication
    "allauth.socialaccount",  # Social accounts
    "allauth.socialaccount.providers.google",  # Google login
    "allauth.socialaccount.providers.apple",  # Apple login
    "dj_rest_auth",  # dj-rest-auth for handling auth endpoints
    "dj_rest_auth.registration",  # Register endpoints for signup/login
    "rest_framework_simplejwt",
    "rest_framework_simplejwt.token_blacklist",
    # Local apps
    "apps.users",
    "apps.task_management",
]

INSTALLED_APPS += EXTERNAL_APPS

SITE_ID = 4  # Required for django-allauth

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "allauth.account.middleware.AccountMiddleware",  # Required for django-allauth
    "corsheaders.middleware.CorsMiddleware",  # CORS
]

ROOT_URLCONF = "core.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "core.wsgi.application"


# Database
# https://docs.djangoproject.com/en/5.2/ref/settings/#databases

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}


# Password validation
# https://docs.djangoproject.com/en/5.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.2/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.2/howto/static-files/

STATIC_URL = "static/"

# Default primary key field type
# https://docs.djangoproject.com/en/5.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

















# Email configuration (for manual email auth)
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = "smtp.gmail.com"
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = "fahad1001mir@gmail.com"  # Your actual email
EMAIL_HOST_PASSWORD = "fqxt qkaf ojng qzwq"  # Your email password or app password
DEFAULT_FROM_EMAIL = EMAIL_HOST_USER

# Custom user model
AUTH_USER_MODEL = "users.CustomUser"

# Authentication Backends (for social login and email)
AUTHENTICATION_BACKENDS = [
    "allauth.account.auth_backends.AuthenticationBackend",  # For allauth authentication
]

# REST framework setup for JWT (both for manual and social login)
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 10,
    'DEFAULT_FILTER_BACKENDS': [
        'django_filters.rest_framework.DjangoFilterBackend',
        'rest_framework.filters.SearchFilter',
        'rest_framework.filters.OrderingFilter',
    ],
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
    'DATETIME_FORMAT': '%Y-%m-%d %H:%M:%S',
    'DATE_FORMAT': '%Y-%m-%d',
}

# JWT Configuration
from datetime import timedelta

# Simple JWT configuration (for JWT token expiration and refresh)
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=30),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=31),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    "AUTH_HEADER_TYPES": ("Bearer",),
}

# Dj-Rest-Auth settings (handles login, registration, etc.)
REST_AUTH = {
    "USER_DETAILS_SERIALIZER": "apps.users.serializers.CustomUserSerializer",  # Custom serializer for user details
    "USE_JWT": True,
}

# Social Account Provider Settings (Google and Apple login)
SOCIALACCOUNT_PROVIDERS = {
    "google": {
        "SCOPE": ["profile", "email"],
        "AUTH_PARAMS": {"access_type": "online"},
        "OAUTH_PKCE_ENABLED": True,
        "APP": {
            "client_id": config("GOOGLE_CLIENT_ID"),
            "secret": config("GOOGLE_CLIENT_SECRET"),
            "key": "",  # Optional: add key if needed
        },
    },
    "apple": {
        "APPS": [
            {
                "client_id": config("APPLE_CLIENT_ID"),
                "secret": config("APPLE_KEY_ID"),
                "key": config("APPLE_TEAM_ID"),
                "settings": {"certificate_key": config("APPLE_CERTIFICATE_KEY")},
            }
        ]
    },
}

# # Allauth settings for manual email authentication
# ACCOUNT_EMAIL_REQUIRED = True
# ACCOUNT_USERNAME_REQUIRED = False
# ACCOUNT_AUTHENTICATION_METHOD = "email"  # Login using email only
# ACCOUNT_EMAIL_VERIFICATION = "mandatory"  # Require email verification
# ACCOUNT_UNIQUE_EMAIL = True  # Ensure email uniqueness
# ACCOUNT_USERNAME_VALIDATORS = None  # Disable username validation, as email is used

# Allauth settings for manual email authentication (Updated to new format)
ACCOUNT_LOGIN_METHODS = {'email'}  # Login using email only (replaces ACCOUNT_AUTHENTICATION_METHOD)
ACCOUNT_SIGNUP_FIELDS = ['email*', 'password1*', 'password2*']  # Required fields (replaces ACCOUNT_EMAIL_REQUIRED and ACCOUNT_USERNAME_REQUIRED)
ACCOUNT_EMAIL_VERIFICATION = "mandatory"  # Require email verification
ACCOUNT_UNIQUE_EMAIL = True  # Ensure email uniqueness
ACCOUNT_USERNAME_VALIDATORS = None  # Disable username validation, as email is used


# Django Allauth and Dj-Rest-Auth JWT integration
REST_USE_JWT = True
