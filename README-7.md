# Password Auditor

A CLI tool for auditing password strength and understanding hash hygiene —
entropy estimation, weak-pattern detection (sequential runs, keyboard walks,
repeats), common-password matching, hash-format identification, and a
salted-hashing demonstration.

![python](https://img.shields.io/badge/python-3.10+-blue?style=flat-square)
![license](https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square)

> This is an **educational strength auditor**, not a password-cracking
> tool. It analyzes the structural properties of a password or hash you
> provide — it does not attempt to guess, brute-force, or crack anyone's
> credentials.

## What it does

1. **`strength.py`** — rates a password as `WEAK` / `MODERATE` / `STRONG`
   based on:
   - Shannon-style entropy estimate (length × log2(character pool size))
   - Common-password matching (small illustrative sample list)
   - Sequential runs (`abcd`, `4321`), repeated characters (`aaaa`),
     keyboard-adjacent patterns (`qwer`, `asdf`)
   - Character-class diversity (upper/lower/digit/symbol)
2. **`hashing.py`**
   - `hash_identify()` — recognizes common hash formats (MD5, SHA-1,
     SHA-256/512, bcrypt, argon2, Unix crypt variants) by structure —
     the same first-pass triage a CTF/forensics challenge starts with
   - `demo_salted_hash()` — demonstrates *why* salting matters: hashing
     the same password twice produces two different stored hashes
3. **`main.py`** — CLI wiring it together

## Quick start

```bash
cd src
python3 main.py --check "YourPasswordHere"
python3 main.py                                    # prompts securely (hidden input)
python3 main.py --identify-hash "5f4dcc3b5aa765d61d8327deb882cf99"
python3 main.py --demo-salt "YourPasswordHere"
```

No external dependencies — pure Python standard library (`hashlib`, `math`, `re`, `getpass`).

## Why this project

Demonstrates understanding of both sides of password security: how
attackers evaluate password strength (entropy, common patterns) and how
defenders should store credentials (salting, algorithm choice). This is
core knowledge for both offensive password-auditing engagements and
defensive secure-coding reviews.

## Roadmap / ideas for v2

- [ ] Integrate the HaveIBeenPwned Pwned Passwords k-anonymity API for
      real breach-list checking (no full password ever leaves the machine)
- [ ] Add bcrypt/argon2 hashing demos (currently sha256 for stdlib-only simplicity)
- [ ] Batch-audit a list of passwords from a file

## License

MIT
