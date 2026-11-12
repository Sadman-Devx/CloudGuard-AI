import os

import dj_database_url

from .base import *  # noqa: F401,F403

DEBUG = False
AI_PROVIDER = "mock"
META_API_KEY = ""
META_MODEL_ID = ""
SECRET_KEY = "test-secret-key"
ALLOWED_HOSTS = ["testserver", "localhost"]

# Fast in-memory SQLite by default; set TEST_DATABASE_URL to run the suite on PostgreSQL (CI does).
DATABASES = {"default": dj_database_url.parse(os.environ.get("TEST_DATABASE_URL", "sqlite://:memory:"))}

# The suite makes hundreds of writes from one client address; tests of the limits patch these.
REST_FRAMEWORK = {  # noqa: F405
    **REST_FRAMEWORK,  # noqa: F405
    "DEFAULT_THROTTLE_RATES": {**REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"], "write": "100000/min"},  # noqa: F405
}

PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]

LOGGING = {"version": 1, "disable_existing_loggers": True}
