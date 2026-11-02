import hashlib
import hmac
import os
import re
import secrets
import time
from typing import Tuple, Optional, Dict
from collections import defaultdict


# OWASP Recommended PBKDF2 Parameters (2024/2026)
PBKDF2_ALGORITHM = "sha256"
PBKDF2_ITERATIONS = 600_000
SALT_BYTES = 16


def hash_password(password: str) -> str:
    """
    Cryptographically hashes a plain password using PBKDF2-HMAC-SHA256 with 600,000 iterations
    and a cryptographically random 16-byte salt.
    Format: pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>
    """
    if not password:
        raise ValueError("Password cannot be empty")
    salt = secrets.token_bytes(SALT_BYTES)
    derived = hashlib.pbkdf2_hmac(
        PBKDF2_ALGORITHM,
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )
    return f"pbkdf2_{PBKDF2_ALGORITHM}${PBKDF2_ITERATIONS}${salt.hex()}${derived.hex()}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plain password against a stored PBKDF2-HMAC-SHA256 hash using constant-time comparison.
    """
    if not plain_password or not hashed_password:
        return False
    try:
        parts = hashed_password.split("$")
        if len(parts) != 4 or parts[0] != f"pbkdf2_{PBKDF2_ALGORITHM}":
            return False
        iterations = int(parts[1])
        salt = bytes.fromhex(parts[2])
        expected_hash = bytes.fromhex(parts[3])

        candidate_hash = hashlib.pbkdf2_hmac(
            PBKDF2_ALGORITHM,
            plain_password.encode("utf-8"),
            salt,
            iterations,
        )
        return hmac.compare_digest(candidate_hash, expected_hash)
    except Exception:
        return False


def validate_password_strength(password: str) -> Tuple[bool, Optional[str]]:
    """
    Validates password complexity against international security baselines:
    - Minimum 8 characters (max 128)
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number or special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if len(password) > 128:
        return False, "Password cannot exceed 128 characters."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[\d\W_]", password):
        return False, "Password must contain at least one digit or special character."
    return True, None


def generate_verification_token() -> str:
    """Generates a high-entropy cryptographically random URL-safe token (256-bit)."""
    return secrets.token_urlsafe(32)


class AuthRateLimiter:
    """
    In-memory sliding window rate limiter to protect authentication endpoints
    against credential stuffing and brute-force attacks.
    Can fall back to Redis when distributed state is active.
    """
    def __init__(self, max_attempts: int = 5, window_seconds: int = 300):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._attempts: Dict[str, list[float]] = defaultdict(list)

    def is_rate_limited(self, identifier: str) -> bool:
        now = time.time()
        cutoff = now - self.window_seconds
        # Clean expired timestamps
        history = [ts for ts in self._attempts[identifier] if ts > cutoff]
        self._attempts[identifier] = history
        return len(history) >= self.max_attempts

    def record_attempt(self, identifier: str) -> None:
        now = time.time()
        self._attempts[identifier].append(now)

    def reset(self, identifier: str) -> None:
        if identifier in self._attempts:
            del self._attempts[identifier]


auth_rate_limiter = AuthRateLimiter(max_attempts=5, window_seconds=300)

