"""
Sanitization, validation and security utilities for CYBER ENGINE SDK.
Language-agnostic rules for PII/Secret scrubbing, payload size bounding, and URL safety.
"""

import re
from typing import Any, Dict, List, Set, Union
from urllib.parse import urlparse

# Universal pattern for sensitive keys to automatically redact
SENSITIVE_KEY_PATTERNS = [
    r"password", r"passwd", r"pwd",
    r"secret", r"api[_-]?key", r"access[_-]?token", r"auth[_-]?token",
    r"authorization", r"bearer", r"jwt", r"private[_-]?key",
    r"credit[_-]?card", r"card[_-]?number", r"cvv", r"cvc",
    r"ssn", r"social[_-]?security",
]
_COMPILED_SENSITIVE_RE = re.compile("|".join(SENSITIVE_KEY_PATTERNS), re.IGNORECASE)

MAX_ATTRIBUTE_KEYS = 200
MAX_STRING_LENGTH = 10_000
MAX_PAYLOAD_BYTES = 1_048_576  # 1 MB


def sanitize_attributes(
    data: Any,
    redacted_val: str = "[REDACTED]",
    max_depth: int = 6,
    current_depth: int = 0
) -> Any:
    """
    Recursively scrubs sensitive keys and truncates unbounded strings in attributes/provenance.
    Works on nested dicts, lists, and primitives.
    """
    if current_depth > max_depth:
        return "[MAX_DEPTH_EXCEEDED]"

    if isinstance(data, dict):
        sanitized = {}
        for count, (k, v) in enumerate(data.items()):
            if count >= MAX_ATTRIBUTE_KEYS:
                sanitized["_truncated_keys_count"] = len(data) - MAX_ATTRIBUTE_KEYS
                break
            
            # Key matching check
            if _COMPILED_SENSITIVE_RE.search(str(k)):
                sanitized[str(k)] = redacted_val
            else:
                sanitized[str(k)] = sanitize_attributes(v, redacted_val, max_depth, current_depth + 1)
        return sanitized

    if isinstance(data, (list, tuple, set)):
        return [sanitize_attributes(item, redacted_val, max_depth, current_depth + 1) for item in list(data)[:100]]

    if isinstance(data, str):
        if len(data) > MAX_STRING_LENGTH:
            return data[:MAX_STRING_LENGTH] + "...[TRUNCATED]"
        return data

    return data


def validate_endpoint_url(endpoint: str, allow_insecure_http: bool = False) -> str:
    """
    Validates the cyber engine endpoint URL.
    Enforces HTTPS unless explicitly overridden or pointing to localhost/loopback.
    """
    cleaned = endpoint.strip().rstrip("/")
    if not cleaned.startswith(("http://", "https://")):
        cleaned = f"https://{cleaned}"

    parsed = urlparse(cleaned)
    if not parsed.netloc:
        raise ValueError(f"Invalid CYBER ENGINE endpoint URL: '{endpoint}'")

    hostname = parsed.hostname or ""
    is_localhost = hostname in ("localhost", "127.0.0.1", "::1", "0.0.0.0", "testserver")

    if parsed.scheme == "http" and not is_localhost and not allow_insecure_http:
        raise ValueError(
            f"Security Violation: Insecure HTTP is prohibited for remote endpoint '{endpoint}'. "
            "Use HTTPS or set allow_insecure_http=True only for local testing environments."
        )

    return cleaned

