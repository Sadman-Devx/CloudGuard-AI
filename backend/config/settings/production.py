from django.core.exceptions import ImproperlyConfigured

from .base import *  # noqa: F401,F403
from .base import SECRET_KEY, env_list  # noqa: F401

DEBUG = False

if not SECRET_KEY or SECRET_KEY.startswith("replace-with"):
    raise ImproperlyConfigured("DJANGO_SECRET_KEY must be set to a generated secret in production.")

if not env_list("DJANGO_ALLOWED_HOSTS"):
    raise ImproperlyConfigured("DJANGO_ALLOWED_HOSTS must be set explicitly in production.")

SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
# Enable long-duration HSTS only after HTTPS is confirmed working.
SECURE_HSTS_SECONDS = 0
