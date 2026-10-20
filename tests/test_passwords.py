"""backend/passwords.py: salted PBKDF2 hashes, legacy sha256 hex, and the
per-process cache that keeps Basic Auth cheap without caching failures."""

import hashlib
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import passwords  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_cache():
    passwords.clear_cache()
    yield
    passwords.clear_cache()


def test_hash_is_salted_pbkdf2_and_verifies():
    a = passwords.hash_password('correct horse', iterations=1000)
    b = passwords.hash_password('correct horse', iterations=1000)
    assert a.startswith('pbkdf2_sha256$1000$')
    assert a != b, 'a fresh salt per call'
    assert passwords.verify_password('correct horse', a)
    assert passwords.verify_password('correct horse', b)
    assert not passwords.verify_password('correct horsf', a)
    assert 'correct horse' not in a


def test_default_iterations_meet_owasp_floor():
    assert passwords.PBKDF2_ITERATIONS >= 600_000
    assert passwords.hash_password('x').split('$')[1] == str(passwords.PBKDF2_ITERATIONS)


def test_legacy_sha256_hex_still_verifies():
    legacy = hashlib.sha256(b'hunter2').hexdigest()
    assert passwords.is_legacy_hash(legacy)
    assert passwords.verify_password('hunter2', legacy)
    assert not passwords.verify_password('hunter3', legacy)


@pytest.mark.parametrize('stored', [
    '', 'plaintext', 'é' * 64, 'pbkdf2_sha256$0$AA==$AA==', 'pbkdf2_sha256$1000$!!$!!',
    'pbkdf2_sha256$1000$$', 'pbkdf2_sha512$1000$AA==$AA==', None, 42, {'a': 1},
])
def test_malformed_stored_value_denies_without_raising(stored):
    assert passwords.verify_password('anything', stored) is False


@pytest.mark.parametrize('stored, valid', [
    ('a' * 64, True),
    ('A' * 64, False),
    ('pbkdf2_sha256$600000$c2FsdA==$aGFzaA==', True),
    ('pbkdf2_sha256$x$c2FsdA==$aGFzaA==', False),
    ('nope', False),
])
def test_is_valid_stored_hash(stored, valid):
    assert passwords.is_valid_stored_hash(stored) is valid


def test_empty_password_cannot_be_hashed():
    with pytest.raises(ValueError):
        passwords.hash_password('')


def test_successful_verification_is_cached_but_failures_are_not(monkeypatch):
    stored = passwords.hash_password('pw', iterations=1000)
    calls = []
    real = passwords._verify_uncached

    def counting(password, s):
        calls.append(password)
        return real(password, s)

    monkeypatch.setattr(passwords, '_verify_uncached', counting)
    assert passwords.verify_password('pw', stored)
    assert passwords.verify_password('pw', stored)
    assert calls == ['pw'], 'second success served from cache'
    assert not passwords.verify_password('bad', stored)
    assert not passwords.verify_password('bad', stored)
    assert calls == ['pw', 'bad', 'bad'], 'every failure pays the full cost'


def test_cache_is_keyed_by_stored_hash_so_rotation_invalidates(monkeypatch):
    old = passwords.hash_password('pw', iterations=1000)
    new = passwords.hash_password('pw2', iterations=1000)
    assert passwords.verify_password('pw', old)
    assert not passwords.verify_password('pw', new)


def test_cache_entries_expire(monkeypatch):
    stored = passwords.hash_password('pw', iterations=1000)
    assert passwords.verify_password('pw', stored)
    calls = []
    monkeypatch.setattr(passwords, '_verify_uncached',
                        lambda p, s: calls.append(p) or True)
    now = [1_000_000.0]
    monkeypatch.setattr(passwords.time, 'monotonic', lambda: now[0])
    passwords.clear_cache()
    assert passwords.verify_password('pw', stored)
    assert calls == ['pw']
    now[0] += passwords._CACHE_TTL_S - 1
    assert passwords.verify_password('pw', stored)
    assert calls == ['pw']
    now[0] += 2
    assert passwords.verify_password('pw', stored)
    assert calls == ['pw', 'pw']


def test_cache_never_holds_the_password():
    stored = passwords.hash_password('s3cret-value', iterations=1000)
    assert passwords.verify_password('s3cret-value', stored)
    assert 's3cret-value' not in repr(passwords._cache)
