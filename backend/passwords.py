"""Password hashing for the HTTP Basic Auth gate.

Two stored formats are accepted:

``pbkdf2_sha256$<iterations>$<salt_b64>$<hash_b64>``
    Written by ``scripts/set_lde_password.py``. Salted PBKDF2-HMAC-SHA256
    (stdlib ``hashlib.pbkdf2_hmac``) so a leaked ``lde/basic-auth`` secret
    cannot be turned back into the password with a rainbow table.

64 lowercase hex characters
    The legacy unsalted ``sha256(password)``. Still verified so a secret
    written before this module existed keeps working. Re-run
    ``scripts/set_lde_password.py`` to move to the salted format.

Basic Auth sends the credentials on every request, so ``verify_password``
remembers each successful verification for ``_CACHE_TTL_S`` seconds, keyed by
the stored hash and a SHA-256 of the presented password (never the password
itself). A rotated secret changes the key, so the old password stops working
as soon as the new secret is read. Failed attempts are never cached: every
wrong guess pays the full PBKDF2 cost.
"""

import base64
import hashlib
import hmac
import os
import re
import threading
import time

PBKDF2_ITERATIONS = 600_000  # OWASP 2023 recommendation for PBKDF2-HMAC-SHA256
_SALT_BYTES = 16
_PBKDF2_RE = re.compile(r'^pbkdf2_sha256\$(\d{1,9})\$([A-Za-z0-9+/=]+)\$([A-Za-z0-9+/=]+)$')
_LEGACY_SHA256_RE = re.compile(r'^[0-9a-f]{64}$')

_CACHE_TTL_S = 300
_CACHE_MAX = 256
_cache = {}  # (stored_hash, sha256(password)) -> monotonic time of verification
_cache_lock = threading.Lock()


def hash_password(password, iterations=PBKDF2_ITERATIONS):
    """Return a ``pbkdf2_sha256$...`` string for *password* with a fresh salt."""
    if not isinstance(password, str) or password == '':
        raise ValueError('password is empty')
    salt = os.urandom(_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
    return 'pbkdf2_sha256${}${}${}'.format(
        iterations,
        base64.b64encode(salt).decode('ascii'),
        base64.b64encode(digest).decode('ascii'),
    )


def is_valid_stored_hash(stored):
    """True when *stored* is in one of the two accepted formats."""
    if not isinstance(stored, str):
        return False
    return bool(_PBKDF2_RE.match(stored) or _LEGACY_SHA256_RE.match(stored))


def is_legacy_hash(stored):
    """True for the unsalted sha256 hex format."""
    return isinstance(stored, str) and bool(_LEGACY_SHA256_RE.match(stored))


def _verify_uncached(password, stored):
    m = _PBKDF2_RE.match(stored)
    if m:
        iterations = int(m.group(1))
        try:
            salt = base64.b64decode(m.group(2), validate=True)
            expected = base64.b64decode(m.group(3), validate=True)
        except ValueError:
            return False
        if iterations < 1 or not salt or not expected:
            return False
        actual = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations,
                                     dklen=len(expected))
        return hmac.compare_digest(actual, expected)
    if _LEGACY_SHA256_RE.match(stored):
        actual = hashlib.sha256(password.encode('utf-8')).hexdigest()
        return hmac.compare_digest(actual.encode('ascii'), stored.encode('ascii'))
    return False


def verify_password(password, stored):
    """True when *password* matches *stored*. Never raises on a malformed value."""
    if not isinstance(password, str) or not isinstance(stored, str):
        return False
    key = (stored, hashlib.sha256(password.encode('utf-8')).hexdigest())
    now = time.monotonic()
    with _cache_lock:
        hit = _cache.get(key)
        if hit is not None and now - hit < _CACHE_TTL_S:
            return True
    if not _verify_uncached(password, stored):
        return False
    with _cache_lock:
        if len(_cache) >= _CACHE_MAX:
            stale = [k for k, t in _cache.items() if now - t >= _CACHE_TTL_S]
            for k in stale:
                del _cache[k]
            if len(_cache) >= _CACHE_MAX:
                _cache.clear()
        _cache[key] = now
    return True


def clear_cache():
    """Forget every remembered verification (tests, or after a rotation)."""
    with _cache_lock:
        _cache.clear()
