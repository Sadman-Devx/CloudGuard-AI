"""Rate limits for the API.

Every endpoint that changes state (POST/PUT/PATCH/DELETE) shares one per-client ``write`` budget.
The expensive endpoints (``ai_explain``, ``simulate``) add their own stricter scoped budget on
top; those views opt in with ``throttle_scope`` (see ``ScopedRateThrottle``). Reads are never
throttled here.

Limits are counted in Django's cache, which is **per process** by default. Run a single worker
process (the Dockerfile uses threads) or configure a shared cache, otherwise the effective limit
is multiplied by the number of workers.
"""

from rest_framework.throttling import SimpleRateThrottle

SAFE_METHODS = ("GET", "HEAD", "OPTIONS")


class WriteThrottle(SimpleRateThrottle):
    scope = "write"

    def get_cache_key(self, request, view):
        if request.method in SAFE_METHODS:
            return None  # None means "do not throttle this request"
        return self.cache_format % {"scope": self.scope, "ident": self.get_ident(request)}