from .base import *  # noqa: F401,F403
from .base import ALLOWED_HOSTS as _BASE_HOSTS
from .base import SECRET_KEY as _BASE_SECRET

DEBUG = True

# Development-only fallback; production.py refuses to start without a real key.
SECRET_KEY = _BASE_SECRET or "dev-insecure-key-do-not-use-in-production"

# "backend" is the Docker Compose service name used by the Vite dev proxy.
ALLOWED_HOSTS = [*_BASE_HOSTS, "[::1]", "testserver", "backend"]
