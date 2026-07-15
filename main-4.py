"""
main.py
CLI entry point for the Password Auditor.

Usage:
    python3 main.py --check "MyP@ssw0rd123"
    python3 main.py --identify-hash "5f4dcc3b5aa765d61d8327deb882cf99"
    python3 main.py --demo-salt "MyP@ssw0rd123"
"""
import argparse
import getpass
import strength
import hashing

GREEN = "\033[92m"
DIM = "\033[2m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"
BOLD = "\033[1m"

BANNER = rf"""{GREEN}{BOLD}
  ____                                 _
 |  _ \ __ _ ___ ___ __      _____  _ __| |
 | |_) / _` / __/ __\ \ /\ / / _ \| '__| |
 |  __/ (_| \__ \__ \\ V  V / (_) | |  | |
 |_|   \__,_|___/___/ \_/\_/ \___/|_|  |_|
{RESET}{DIM}      strength & hash-hygiene auditor{RESET}
"""

VERDICT_COLOR = {"STRONG": GREEN, "MODERATE": YELLOW, "WEAK": RED}


def check_password(password):
    result = strength.rate_password(password)
    color = VERDICT_COLOR[result["verdict"]]
    print(f"\n{BOLD}Verdict:{RESET} {color}{result['verdict']}{RESET}")
    print(f"Length: {result['length']}   Estimated entropy: {result['entropy_bits']} bits")
    if result["issues"]:
        print(f"\n{YELLOW}Issues found:{RESET}")
        for issue in result["issues"]:
            print(f"  {YELLOW}-{RESET} {issue}")
    else:
        print(f"\n{GREEN}No common weaknesses detected.{RESET}")


def identify_hash(hash_string):
    label = hashing.hash_identify(hash_string)
    print(f"\n{BOLD}Likely format:{RESET} {GREEN}{label}{RESET}")


def demo_salt(password):
    result = hashing.demo_salted_hash(password)
    print(f"\n{BOLD}Salted hash demo ({result['algorithm']}):{RESET}")
    print(f"  salt : {DIM}{result['salt_hex']}{RESET}")
    print(f"  hash : {GREEN}{result['salted_hash']}{RESET}")
    print(f"\n{DIM}{result['note']}{RESET}")

    # Run it twice to prove the same password -> different hash each time
    result2 = hashing.demo_salted_hash(password)
    print(f"\n{BOLD}Same password, run again (new random salt):{RESET}")
    print(f"  salt : {DIM}{result2['salt_hex']}{RESET}")
    print(f"  hash : {GREEN}{result2['salted_hash']}{RESET}")
    print(f"{DIM}(different hash each time — this is why salting defeats precomputed rainbow tables){RESET}")


def main():
    parser_ = argparse.ArgumentParser(description="Password Auditor")
    parser_.add_argument("--check", metavar="PASSWORD", help="Analyze password strength (prompted securely if omitted)")
    parser_.add_argument("--identify-hash", metavar="HASH", help="Guess a hash's algorithm from its format")
    parser_.add_argument("--demo-salt", metavar="PASSWORD", help="Demonstrate salted hashing")
    args = parser_.parse_args()

    print(BANNER)

    if args.check is not None:
        check_password(args.check)
    elif args.identify_hash:
        identify_hash(args.identify_hash)
    elif args.demo_salt:
        demo_salt(args.demo_salt)
    else:
        pw = getpass.getpass("Enter a password to audit (input hidden): ")
        check_password(pw)


if __name__ == "__main__":
    main()
