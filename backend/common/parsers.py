"""Request parsers that bound untrusted input before it reaches the validator."""

import io

from django.conf import settings
from rest_framework.exceptions import ParseError
from rest_framework.parsers import JSONParser

from common.exceptions import PayloadTooLarge


class BoundedJSONParser(JSONParser):
    """JSON parser with a hard body-size cap and protection against deep nesting.

    The cap is enforced by reading at most ``MAX_UPLOAD_BYTES + 1`` bytes, so it
    also applies to chunked uploads that carry no ``Content-Length`` header.
    """

    def parse(self, stream, media_type=None, parser_context=None):
        limit = settings.MAX_UPLOAD_BYTES
        raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise PayloadTooLarge(f"Request body exceeds the {limit} byte limit.")
        try:
            return super().parse(io.BytesIO(raw), media_type, parser_context)
        except RecursionError as exc:
            raise ParseError("JSON is nested too deeply.") from exc
