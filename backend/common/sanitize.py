"""Text hygiene shared by request validation and the AI prompt builder.

Pure Python (no Django). Two jobs:

* control characters: keep newlines, NULs and escape codes out of labels that end up in the UI,
  logs and HTTP headers;
* secret redaction: imported names and descriptions are free text, and people paste things like
  access keys or passwords into them. Before any text is sent to the Meta model it is scrubbed.

Redaction is best effort (pattern based). The real protection is still: import synthetic or
already-sanitised configurations only. Over-redacting is the safe direction, so the patterns lean
towards removing too much rather than too little.
"""

from __future__ import annotations

import re

REDACTED = "[REDACTED]"

# Bounds the work done on a single string; schema-validated text is far shorter than this.
MAX_REDACT_INPUT = 2_000

# C0 controls (tab and newline included) and DEL, the same set the configuration importer rejects.
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def has_control_chars(text: str) -> bool:
    return _CONTROL.search(text) is not None


def strip_control_chars(text: str) -> str:
    return _CONTROL.sub("", text)


# ---- secret redaction -------------------------------------------------------------------------

_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*", re.DOTALL)
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}")
_KEY_VALUE = re.compile(
    r"(?i)\b(password|passwd|pwd|passphrase|secret(?:[_ -]?(?:access[_ -]?)?key)?"
    r"|(?:access|api|auth|private|signing)[_ -]?key|token|credentials?|authorization)\b"
    r"(\s*[:=]\s*)(\S+)"
)
_TOKENS = (
    # AWS access key ids (long-term and temporary) and the other vendor-prefixed identifiers.
    re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA|AGPA|ANPA|ANVA|AIPA)[A-Z0-9]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
)
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
# AWS secret access keys are 40 characters of base64 with mixed case and digits. Requiring all
# three keeps long CamelCase names and hex digests from being flagged.
_BLOB = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=_-])")


def _redact_blob(match: re.Match[str]) -> str:
    blob = match.group(0)
    looks_random = re.search(r"[A-Z]", blob) and re.search(r"[a-z]", blob) and re.search(r"\d", blob)
    return REDACTED if looks_random else blob


def redact_secrets(text: str) -> str:
    """Replace credentials, tokens and e-mail addresses in free text with ``[REDACTED]``."""
    text = text[:MAX_REDACT_INPUT]
    text = _PRIVATE_KEY.sub(REDACTED, text)
    text = _BEARER.sub(f"Bearer {REDACTED}", text)
    text = _KEY_VALUE.sub(rf"\1\2{REDACTED}", text)
    for pattern in _TOKENS:
        text = pattern.sub(REDACTED, text)
    text = _EMAIL.sub(REDACTED, text)
    return _BLOB.sub(_redact_blob, text)