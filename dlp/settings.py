import os
import json
import secrets
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / '.env')
SECRET_KEY = os.getenv('DJANGO_SECRET_KEY') or secrets.token_urlsafe(64)
DEBUG = False
ALLOWED_HOSTS = os.getenv('DJANGO_ALLOWED_HOSTS', 'localhost,127.0.0.1,testserver').split(',')
ROOT_URLCONF = 'dlp.urls'
CSRF_FAILURE_VIEW = 'dlp.views.csrf_failure'
WSGI_APPLICATION = 'dlp.wsgi.application'
INSTALLED_APPS = ['django.contrib.admin', 'django.contrib.auth', 'django.contrib.contenttypes', 'django.contrib.sessions', 'django.contrib.messages', 'django.contrib.staticfiles', 'dlp']
MIDDLEWARE = ['django.middleware.security.SecurityMiddleware', 'dlp.views.GatewaySecurityMiddleware', 'django.contrib.sessions.middleware.SessionMiddleware', 'django.middleware.common.CommonMiddleware', 'django.middleware.csrf.CsrfViewMiddleware', 'django.contrib.auth.middleware.AuthenticationMiddleware', 'django.contrib.messages.middleware.MessageMiddleware', 'django.middleware.clickjacking.XFrameOptionsMiddleware']
TEMPLATES = [{'BACKEND': 'django.template.backends.django.DjangoTemplates', 'APP_DIRS': True, 'OPTIONS': {'context_processors': ['django.template.context_processors.request', 'django.contrib.auth.context_processors.auth', 'django.contrib.messages.context_processors.messages']}}]
DATABASES = {'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': BASE_DIR / 'db.sqlite3'}}
CACHES = {'default': {'BACKEND': 'django.core.cache.backends.db.DatabaseCache', 'LOCATION': 'dlp_rate_cache'}}
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
USE_TZ = True
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
DLP_MAX_PROMPT_LENGTH = 16000
DATA_UPLOAD_MAX_MEMORY_SIZE = 70000
DATA_UPLOAD_MAX_NUMBER_FIELDS = 5
DLP_RATE_LIMIT = int(os.getenv('DLP_RATE_LIMIT', '30'))
DLP_RATE_WINDOW = 60
DLP_ENABLE_LOCAL_CLASSIFIER = os.getenv('DLP_ENABLE_LOCAL_CLASSIFIER', 'false').lower() == 'true'
DLP_LOCAL_MODEL_PATH = os.getenv('DLP_LOCAL_MODEL_PATH', '')
DLP_ENABLE_PRESIDIO = os.getenv('DLP_ENABLE_PRESIDIO', 'false').lower() == 'true'
DLP_GUARD_MODELS = json.loads(os.getenv('DLP_GUARD_MODELS', '[]'))
DLP_SPACY_MODEL = os.getenv('DLP_SPACY_MODEL', 'en_core_web_lg')
DLP_INTERNAL_KEYWORDS = [v.strip() for v in os.getenv('DLP_INTERNAL_KEYWORDS', 'TEST-ORION').split(',') if v.strip()]
DLP_INTERNAL_DOMAINS = [v.strip() for v in os.getenv('DLP_INTERNAL_DOMAINS', 'corp.example,internal.example').split(',') if v.strip()]
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_NAME = 'dlp_sessionid'
CSRF_COOKIE_NAME = 'dlp_csrftoken'
SESSION_COOKIE_SAMESITE = 'Strict'
CSRF_COOKIE_SAMESITE = 'Strict'
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = 'same-origin'
SECURE_SSL_REDIRECT = os.getenv('DLP_REQUIRE_HTTPS', 'false').lower() == 'true'
SESSION_COOKIE_SECURE = SECURE_SSL_REDIRECT
CSRF_COOKIE_SECURE = SECURE_SSL_REDIRECT
SECURE_HSTS_SECONDS = 31536000 if SECURE_SSL_REDIRECT else 0
X_FRAME_OPTIONS = 'DENY'
# Never emit request/exception details to console or email handlers.
LOGGING = {'version': 1, 'disable_existing_loggers': True, 'handlers': {'safe': {'class': 'logging.StreamHandler'}}, 'loggers': {'dlp.safe': {'handlers': ['safe'], 'level': 'WARNING', 'propagate': False}}}
