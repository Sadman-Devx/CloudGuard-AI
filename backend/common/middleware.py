"""Request-ID middleware: every response carries ``X-Request-ID`` for tracing."""

import re
import uuid

_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{8,64}$")


class RequestIdMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        incoming = request.headers.get("X-Request-ID", "")
        # Only trust well-formed client IDs; never reflect arbitrary header text.
        request.request_id = incoming if _SAFE_REQUEST_ID.match(incoming) else uuid.uuid4().hex
        response = self.get_response(request)
        response["X-Request-ID"] = request.request_id
        return response
