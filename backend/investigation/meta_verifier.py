"""
Meta API Verification and Safeguards for CYBER ENGINE Deep-Investigation Path.

Verifies official Meta model identifiers, API endpoints, authentication standards,
and enforces safety guards against credential leakage and unbounded context sizes.
"""

import re
from typing import Set, Optional, Dict, Any

# Official Meta Model Identifiers (Llama 3 / 3.1 / 3.2 / 3.3, Muse Spark / Wonder, and Llama Guard)
OFFICIAL_META_MODELS: Set[str] = {
    # Official Meta Dev Platform Models (dev.meta.ai)
    "muse-spark-1.3",
    "muse-spark-1.3-contributor",
    "muse-wonder-1.0",
    "muse-spark-1.2",
    "muse-spark-1.2-contributor",
    "muse-spark-1.1",
    "muse-glimmer",
    # Flagship Meta Llama 3.3
    "Llama-3.3-70B-Instruct",
    "meta-llama/Llama-3.3-70B-Instruct",
    # Meta Llama 3.1
    "Llama-3.1-405B-Instruct",
    "meta-llama/Llama-3.1-405B-Instruct",
    "Llama-3.1-70B-Instruct",
    "meta-llama/Llama-3.1-70B-Instruct",
    "Llama-3.1-8B-Instruct",
    "meta-llama/Llama-3.1-8B-Instruct",
    # Meta Llama 3.2 (Lightweight and Vision)
    "Llama-3.2-3B-Instruct",
    "meta-llama/Llama-3.2-3B-Instruct",
    "Llama-3.2-1B-Instruct",
    "meta-llama/Llama-3.2-1B-Instruct",
    "Llama-3.2-11B-Vision-Instruct",
    "meta-llama/Llama-3.2-11B-Vision-Instruct",
    "Llama-3.2-90B-Vision-Instruct",
    "meta-llama/Llama-3.2-90B-Vision-Instruct",
    # Safety Models
    "Llama-Guard-3-8B",
    "meta-llama/Llama-Guard-3-8B",
}

# Official API endpoints
OFFICIAL_META_API_BASE_URL = "https://api.meta.ai/v1"
FALLBACK_META_API_BASE_URL = "https://api.llama.com/v1"

# Bounds
MAX_CONTEXT_TIMELINE_EVENTS = 50
MAX_EVENT_ATTRIBUTE_LENGTH = 500
MAX_MODEL_OUTPUT_TOKENS = 4096


def is_genuine_meta_model(model_identifier: str) -> bool:
    """
    Verifies that the configured model is genuinely a recognized Meta Llama model
    and not an unsupported or generic placeholder.
    """
    if not model_identifier:
        return False
    normalized = model_identifier.strip()
    if normalized in OFFICIAL_META_MODELS:
        return True
    # Also support versioned sub-variants following standard Meta naming conventions
    pattern = r"^(meta-llama/)?(Llama-(3\.[123]|Guard-3)-.*|muse-(spark|wonder|glimmer).*)$"
    return bool(re.match(pattern, normalized, re.IGNORECASE))


def sanitize_sensitive_data(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Redacts credentials, API keys, passwords, and tokens before logging
    or sending telemetry to external services.
    """
    sensitive_keys = {
        "api_key", "token", "password", "secret", "authorization",
        "access_token", "refresh_token", "credit_card", "ssn"
    }

    sanitized = {}
    for k, v in payload.items():
        if any(s in k.lower() for s in sensitive_keys):
            sanitized[k] = "[REDACTED]"
        elif isinstance(v, dict):
            sanitized[k] = sanitize_sensitive_data(v)
        elif isinstance(v, list):
            sanitized[k] = [
                sanitize_sensitive_data(item) if isinstance(item, dict) else item
                for item in v
            ]
        else:
            sanitized[k] = v
    return sanitized


def bound_investigation_timeline(events: list, max_events: int = MAX_CONTEXT_TIMELINE_EVENTS) -> list:
    """
    Ensures the investigation timeline context does not exceed token safety bounds.
    Retains the most chronologically relevant events.
    """
    if len(events) <= max_events:
        return events
    # If exceeding, retain first 10 (early signals) and last (max_events - 10) (recent escalation)
    return events[:10] + events[-(max_events - 10):]

