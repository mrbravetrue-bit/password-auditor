"""
hashing.py
Two educational pieces:
  1. hash_identify() — recognizes common hash formats *by structure*
     (length/charset/prefix), the same way a CTF/forensics analyst does a
     first-pass triage. It does not crack anything.
  2. demo_salted_hash() — demonstrates *why* salting matters by showing
     that the same password produces different hashes with different
     salts, and the same hash with the same salt (deterministic).
"""
import hashlib
import os
import re

HASH_PATTERNS = [
    (r"^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$", "bcrypt"),
    (r"^\$argon2(id|i|d)\$", "argon2"),
    (r"^\$6\$", "SHA-512 crypt (Unix)"),
    (r"^\$5\$", "SHA-256 crypt (Unix)"),
    (r"^\$1\$", "MD5 crypt (Unix, legacy — weak)"),
    (r"^[a-fA-F0-9]{32}$", "MD5 (raw) — weak, no salting, fast to brute-force"),
    (r"^[a-fA-F0-9]{40}$", "SHA-1 (raw) — weak, deprecated for security use"),
    (r"^[a-fA-F0-9]{64}$", "SHA-256 (raw) — strong hash function, but fast (bad for passwords unless salted+stretched)"),
    (r"^[a-fA-F0-9]{128}$", "SHA-512 (raw) — same caveat as SHA-256"),
]


def hash_identify(hash_string):
    """Returns a best-guess label for the hash's algorithm family, based
    purely on its structural format (length, prefix, charset)."""
    hash_string = hash_string.strip()
    for pattern, label in HASH_PATTERNS:
        if re.match(pattern, hash_string):
            return label
    return "Unrecognized format — could be a custom encoding or a salted hash with a non-standard prefix."


def demo_salted_hash(password, algorithm="sha256"):
    """Demonstrates salted hashing: generates a random salt, hashes the
    password with it, and returns both — illustrating why the same
    password produces a different stored hash each time it's set.
    """
    salt = os.urandom(16)
    h = hashlib.new(algorithm)
    h.update(salt + password.encode())
    digest = h.hexdigest()
    return {
        "algorithm": algorithm,
        "salt_hex": salt.hex(),
        "salted_hash": digest,
        "note": "Storing salt+hash together lets you verify a password later "
                "without ever storing the plaintext, and means two users with "
                "the same password get different stored hashes.",
    }


def verify_salted_hash(password, salt_hex, expected_hash, algorithm="sha256"):
    salt = bytes.fromhex(salt_hex)
    h = hashlib.new(algorithm)
    h.update(salt + password.encode())
    return h.hexdigest() == expected_hash
