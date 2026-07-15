"""
strength.py
Password strength analysis: entropy estimation, character-class diversity,
common-password matching, and common weak-pattern detection (sequential
runs, repeated characters, keyboard walks).

This audits password *strength characteristics* — it does not attempt to
crack or brute-force any real password.
"""
import math
import re

# A small illustrative sample of extremely common passwords — enough to
# demonstrate the technique. Real audits use full breach-derived lists
# (e.g. HaveIBeenPwned's Pwned Passwords API/dataset).
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty",
    "abc123", "password1", "111111", "123123", "admin", "letmein",
    "welcome", "monkey", "iloveyou", "dragon", "sunshine", "master",
    "football", "shadow", "superman", "trustno1", "passw0rd",
}

KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]


def _char_pool_size(password):
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32  # rough estimate for common symbol set
    return pool


def calculate_entropy(password):
    """Shannon-style entropy estimate in bits: length * log2(pool size)."""
    pool = _char_pool_size(password)
    if pool == 0 or len(password) == 0:
        return 0.0
    return round(len(password) * math.log2(pool), 1)


def detect_sequential_run(password, min_run=4):
    """Detects ascending/descending sequences like 'abcd' or '4321'."""
    lower = password.lower()
    for i in range(len(lower) - min_run + 1):
        chunk = lower[i:i + min_run]
        codes = [ord(c) for c in chunk]
        if all(codes[j] + 1 == codes[j + 1] for j in range(len(codes) - 1)):
            return chunk
        if all(codes[j] - 1 == codes[j + 1] for j in range(len(codes) - 1)):
            return chunk
    return None


def detect_repeated_chars(password, min_run=4):
    """Detects a single character repeated min_run+ times, e.g. 'aaaa'."""
    match = re.search(r"(.)\1{" + str(min_run - 1) + ",}", password)
    return match.group(0) if match else None


def detect_keyboard_walk(password, min_run=4):
    """Detects adjacent-key sequences like 'qwer' or 'asdf'."""
    lower = password.lower()
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - min_run + 1):
            chunk = row[i:i + min_run]
            if chunk in lower or chunk[::-1] in lower:
                return chunk
    return None


def rate_password(password):
    """Returns a strength report dict for the given password."""
    entropy = calculate_entropy(password)
    issues = []

    if len(password) < 12:
        issues.append(f"Short length ({len(password)} chars) — 12+ is recommended.")
    if password.lower() in COMMON_PASSWORDS:
        issues.append("Matches a commonly breached/used password.")
    seq = detect_sequential_run(password)
    if seq:
        issues.append(f"Contains a sequential run: '{seq}'.")
    rep = detect_repeated_chars(password)
    if rep:
        issues.append(f"Contains repeated characters: '{rep}'.")
    walk = detect_keyboard_walk(password)
    if walk:
        issues.append(f"Contains a keyboard-adjacent pattern: '{walk}'.")
    if not re.search(r"[A-Z]", password):
        issues.append("No uppercase letters.")
    if not re.search(r"[0-9]", password):
        issues.append("No digits.")
    if not re.search(r"[^a-zA-Z0-9]", password):
        issues.append("No special characters.")

    if entropy >= 80 and not issues:
        verdict = "STRONG"
    elif entropy >= 50 and len(issues) <= 1:
        verdict = "MODERATE"
    else:
        verdict = "WEAK"

    return {
        "length": len(password),
        "entropy_bits": entropy,
        "verdict": verdict,
        "issues": issues,
    }
