"""Shared Django settings for CloudGuard AI."""

import os
from pathlib import Path

import dj_database_url
from dotenv import load_dotenv

# backend/config/settings/base.py -> parents[2] == backend/
BASE_DIR = Path(__file__).resolve().parents[2]

load_dotenv(BASE_DIR.parent / ".env")
load_dotenv(BASE_DIR / ".env")


def env_list(name: str, default: str = "") -> list[str]:
    return [item.strip() for item in os.environ.get(name, default).split(",") if item.strip()]


SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "")

DEBUG = False

ALLOWED_HOSTS = env_list("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # Third party
    "rest_framework",
    "corsheaders",
    "drf_spectacular",
    # Local apps
    "apps.projects.apps.ProjectsConfig",
    "apps.cloud_resources.apps.CloudResourcesConfig",
    "apps.security_engine.apps.SecurityEngineConfig",
    "apps.ai_copilot.apps.AiCopilotConfig",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "common.middleware.RequestIdMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

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

WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

# Database: DATABASE_URL (PostgreSQL in Docker/production). Falls back to SQLite
# only when DATABASE_URL is unset so local tooling and tests work without a server.
DATABASES = {
    "default": dj_database_url.config(
        env="DATABASE_URL",
        default=f"sqlite:///{BASE_DIR / 'db.sqlite3'}",
        conn_max_age=60,
    )
}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

REST_FRAMEWORK = {
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    "DEFAULT_PARSER_CLASSES": ["common.parsers.BoundedJSONParser"],
    "DEFAULT_PAGINATION_CLASS": "common.pagination.StandardPagination",
    "PAGE_SIZE": 50,
    "EXCEPTION_HANDLER": "common.exceptions.api_exception_handler",
    # MVP has no user accounts; every endpoint is open. Tighten before multi-user.
    "DEFAULT_AUTHENTICATION_CLASSES": [],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.AllowAny"],
    "DEFAULT_THROTTLE_CLASSES": [],
    "DEFAULT_THROTTLE_RATES": {"ai_explain": os.environ.get("AI_EXPLAIN_RATE", "30/min")},
}

SPECTACULAR_SETTINGS = {
    "TITLE": "CloudGuard AI API",
    "DESCRIPTION": "AI-powered cloud network security copilot with digital twin simulation.",
    "VERSION": "0.1.0",
    "SERVE_INCLUDE_SCHEMA": False,
}

CORS_ALLOWED_ORIGINS = env_list("CORS_ALLOWED_ORIGINS", "http://localhost:5173")
CSRF_TRUSTED_ORIGINS = env_list("CSRF_TRUSTED_ORIGINS", "http://localhost:5173")

APP_VERSION = "0.5.0"

# Sample configuration fixtures offered by the import screen (read-only, allow-listed by name).
FIXTURES_DIR = Path(os.environ.get("FIXTURES_DIR", BASE_DIR.parent / "sample_data" / "aws"))

# Upload limits (bytes / nesting) for untrusted configuration JSON.
MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", 1_000_000))
DATA_UPLOAD_MAX_MEMORY_SIZE = MAX_UPLOAD_BYTES + 100_000
MAX_JSON_DEPTH = int(os.environ.get("MAX_JSON_DEPTH", 12))

# Meta Model API (Day 5). Everything is configurable; nothing is hard-coded to one model.
META_API_KEY = os.environ.get("META_API_KEY", "")
META_MODEL_ID = os.environ.get("META_MODEL_ID", "")
META_API_BASE_URL = os.environ.get("META_API_BASE_URL", "") or "https://api.meta.ai"
META_CHAT_PATH = os.environ.get("META_CHAT_PATH", "/v1/chat/completions")
# Ask the API for JSON mode (response_format). Off by default: output is validated either way.
META_JSON_MODE = os.environ.get("META_JSON_MODE", "false").lower() in ("1", "true", "yes")

# "meta" calls the Meta Model API; "mock" is an offline demo provider that is always labelled as
# such in the UI. Default: meta when a key and model are configured, otherwise mock.
AI_PROVIDER = os.environ.get("AI_PROVIDER", "") or ("meta" if META_API_KEY and META_MODEL_ID else "mock")
AI_TIMEOUT_SECONDS = float(os.environ.get("AI_TIMEOUT_SECONDS", 30))
AI_MAX_ATTEMPTS = int(os.environ.get("AI_MAX_ATTEMPTS", 2))
# Spending guard: real (non-mock) model calls allowed per rolling hour across the whole app.
AI_MAX_REQUESTS_PER_HOUR = int(os.environ.get("AI_MAX_REQUESTS_PER_HOUR", 60))

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"simple": {"format": "%(asctime)s %(levelname)s %(name)s: %(message)s"}},
    "handlers": {"console": {"class": "logging.StreamHandler", "formatter": "simple"}},
    "root": {"handlers": ["console"], "level": LOG_LEVEL},
}