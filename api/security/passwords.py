"""Password hashing (decision D25).

**No cryptography is invented here.** This is `hashlib.scrypt` from the standard
library — RFC 7914, a memory-hard key derivation function designed for exactly
this — with a random per-password salt and a constant-time comparison.

Why scrypt rather than a dependency: it is already present, it is a KDF designed
for passwords rather than a general hash, and adding `bcrypt` or `argon2-cffi`
would mean a new dependency on a project committed to running offline on an 8 GB
laptop. Why not plain SHA-256: a fast hash is the wrong primitive for a password,
because being fast is precisely what an attacker wants.

Parameters follow the interactive-login profile from RFC 7914 §2: n=2^14, r=8,
p=1. They are recorded **inside the stored hash**, so raising them later does not
invalidate existing passwords — a stored hash carries the parameters it was
created with, and verification reads them back.

Stored format, all fields non-secret except the derived key itself:

    scrypt$<n>$<r>$<p>$<salt-hex>$<derived-key-hex>

Nothing here logs, and nothing here returns a password. The plaintext exists only
as an argument on the stack.
"""

from __future__ import annotations

import hashlib
import hmac
import os

ALGORITHM = "scrypt"

# RFC 7914 §2 interactive-login parameters.
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1

SALT_BYTES = 16
KEY_BYTES = 32

MIN_PASSWORD_LENGTH = 12
"""Short enough not to be theatre, long enough to matter.

Enforced here rather than at the route, so no caller can create an account that
bypasses it.
"""

# scrypt needs roughly 128 * N * r bytes. At n=2^14, r=8 that is ~16 MiB, and
# CPython's default maxmem of 0 rejects anything over 32 MiB — so it is stated
# explicitly rather than left to a default that could change underneath us.
_MAXMEM = 64 * 1024 * 1024


class PasswordError(ValueError):
    """A password was refused before it was ever hashed."""


def hash_password(password: str) -> str:
    """Derive a storable hash. The plaintext is never returned or logged."""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordError(
            f"password must be at least {MIN_PASSWORD_LENGTH} characters; "
            "a short password is not made safe by hashing it well"
        )

    salt = os.urandom(SALT_BYTES)
    derived = _derive(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    return f"{ALGORITHM}${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${derived.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time verification against a stored hash.

    Returns `False` for a malformed stored value rather than raising: a corrupt
    row must not be distinguishable from a wrong password by timing or by
    exception, and it must never authenticate anyone.
    """
    try:
        algorithm, n, r, p, salt_hex, key_hex = stored.split("$")
        if algorithm != ALGORITHM:
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(key_hex)
        derived = _derive(password, salt, int(n), int(r), int(p))
    except (ValueError, TypeError):
        return False

    # hmac.compare_digest, not ==. An early-exit comparison leaks how much of the
    # hash matched, one byte at a time.
    return hmac.compare_digest(derived, expected)


def _derive(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=KEY_BYTES,
        maxmem=_MAXMEM,
    )


def needs_rehash(stored: str) -> bool:
    """Whether a stored hash was made with weaker parameters than current policy.

    Not used automatically — rehashing requires the plaintext, which only exists
    during a successful login. Exposed so that step can be added without changing
    the storage format.
    """
    try:
        algorithm, n, r, p, _, _ = stored.split("$")
    except ValueError:
        return True
    return algorithm != ALGORITHM or int(n) < SCRYPT_N or int(r) < SCRYPT_R or int(p) < SCRYPT_P
