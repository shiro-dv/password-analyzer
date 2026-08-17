#!/usr/bin/env python3
"""
Password Strength Analyzer & Generator
----------------------------------------
Scores password strength using entropy calculation, checks against common
password lists, detects patterns (keyboard walks, repeats, dates), and can
generate cryptographically secure passwords.

Usage:
    python password_analyzer.py --check "MyP@ssw0rd"
    python password_analyzer.py --generate 16
    python password_analyzer.py --interactive
"""
import argparse
import math
import re
import secrets
import string
import sys
from dataclasses import dataclass, field

COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345",
    "1234", "111111", "1234567", "dragon", "123123", "baseball",
    "iloveyou", "trustno1", "1234567890", "sunshine", "master", "welcome",
    "shadow", "ashley", "football", "jesus", "michael", "ninja", "mustang",
    "password1", "admin", "letmein", "monkey", "abc123", "qwerty123",
}

KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]

@dataclass
class PasswordReport:
    password_length: int
    entropy_bits: float
    score: int  # 0-100
    rating: str
    issues: list = field(default_factory=list)
    suggestions: list = field(default_factory=list)


def _char_pool_size(password: str) -> int:
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 33  # approx printable symbols
    return pool or 1


def _shannon_entropy_bits(password: str) -> float:
    """Entropy estimate = length * log2(character pool size)."""
    pool = _char_pool_size(password)
    return len(password) * math.log2(pool)


def _has_keyboard_walk(password: str, min_run: int = 4) -> bool:
    lower = password.lower()
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - min_run + 1):
            chunk = row[i:i + min_run]
            if chunk in lower or chunk[::-1] in lower:
                return True
    return False


def _has_sequential_chars(password: str, min_run: int = 4) -> bool:
    """Detects sequences like abcd, 4321."""
    for i in range(len(password) - min_run + 1):
        window = password[i:i + min_run]
        codes = [ord(c) for c in window]
        if all(codes[j] + 1 == codes[j + 1] for j in range(len(codes) - 1)):
            return True
        if all(codes[j] - 1 == codes[j + 1] for j in range(len(codes) - 1)):
            return True
    return False


def _has_repeated_chars(password: str, min_run: int = 3) -> bool:
    return bool(re.search(r"(.)\1{" + str(min_run - 1) + r",}", password))


def _looks_like_date(password: str) -> bool:
    return bool(re.search(r"(19|20)\d{2}", password)) or bool(
        re.search(r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b", password)
    )


def analyze_password(password: str) -> PasswordReport:
    issues = []
    suggestions = []

    length = len(password)
    entropy = _shannon_entropy_bits(password)

    if password.lower() in COMMON_PASSWORDS:
        issues.append("Password appears in common password lists.")
        suggestions.append("Avoid dictionary words and known leaked passwords.")

    if length < 8:
        issues.append("Too short (under 8 characters).")
        suggestions.append("Use at least 12-16 characters.")
    elif length < 12:
        suggestions.append("Consider 12+ characters for stronger protection.")

    if not re.search(r"[a-z]", password):
        issues.append("Missing lowercase letters.")
    if not re.search(r"[A-Z]", password):
        issues.append("Missing uppercase letters.")
    if not re.search(r"[0-9]", password):
        issues.append("Missing digits.")
    if not re.search(r"[^a-zA-Z0-9]", password):
        issues.append("Missing special characters.")
        suggestions.append("Add symbols like !@#$%^&* to increase entropy.")

    if _has_keyboard_walk(password):
        issues.append("Contains a keyboard walk pattern (e.g., 'qwerty', 'asdf').")
    if _has_sequential_chars(password):
        issues.append("Contains sequential characters (e.g., 'abcd', '1234').")
    if _has_repeated_chars(password):
        issues.append("Contains repeated character runs (e.g., 'aaa').")
    if _looks_like_date(password):
        issues.append("Contains what looks like a year or date — avoid birthdays.")
        suggestions.append("Don't base passwords on personal dates.")

    # Scoring: blend entropy with penalty for each issue found.
    base_score = min(100, (entropy / 80) * 100)  # 80 bits ~ very strong
    penalty = min(base_score, len(issues) * 12)
    score = max(0, round(base_score - penalty))

    if score >= 80:
        rating = "Very Strong"
    elif score >= 60:
        rating = "Strong"
    elif score >= 40:
        rating = "Moderate"
    elif score >= 20:
        rating = "Weak"
    else:
        rating = "Very Weak"

    if not suggestions and rating != "Very Strong":
        suggestions.append("Consider using a passphrase of 4+ random words.")

    return PasswordReport(
        password_length=length,
        entropy_bits=round(entropy, 2),
        score=score,
        rating=rating,
        issues=issues,
        suggestions=suggestions,
    )


def generate_password(length: int = 16, use_symbols: bool = True) -> str:
    """Generates a cryptographically secure random password using `secrets`."""
    if length < 8:
        raise ValueError("Length must be at least 8 for a secure password.")

    alphabet = string.ascii_letters + string.digits
    if use_symbols:
        alphabet += "!@#$%^&*()-_=+[]{}"

    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        # Guarantee at least one of each required character class.
        if (re.search(r"[a-z]", pwd) and re.search(r"[A-Z]", pwd)
                and re.search(r"[0-9]", pwd)
                and (not use_symbols or re.search(r"[^a-zA-Z0-9]", pwd))):
            return pwd


def generate_passphrase(word_count: int = 5) -> str:
    """Generates a Diceware-style passphrase from a small built-in wordlist."""
    words = [
        "correct", "horse", "battery", "staple", "orbit", "velvet", "canyon",
        "ember", "lantern", "quartz", "harbor", "willow", "cipher", "granite",
        "meadow", "falcon", "nimbus", "thistle", "vortex", "amber", "cobalt",
        "juniper", "marble", "opal", "ridge", "shadow", "tundra", "zephyr",
    ]
    return "-".join(secrets.choice(words) for _ in range(word_count))


def print_report(password: str, report: PasswordReport) -> None:
    print(f"\nPassword: {'*' * len(password)}")
    print(f"Length: {report.password_length}")
    print(f"Estimated entropy: {report.entropy_bits} bits")
    print(f"Score: {report.score}/100  ->  {report.rating}")
    if report.issues:
        print("\nIssues found:")
        for issue in report.issues:
            print(f"  - {issue}")
    if report.suggestions:
        print("\nSuggestions:")
        for s in report.suggestions:
            print(f"  - {s}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Password strength analyzer & generator")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check", metavar="PASSWORD", help="Analyze a password's strength")
    group.add_argument("--generate", metavar="LENGTH", type=int, nargs="?", const=16,
                        help="Generate a secure random password (default length 16)")
    group.add_argument("--passphrase", metavar="WORDS", type=int, nargs="?", const=5,
                        help="Generate a diceware-style passphrase")
    group.add_argument("--interactive", action="store_true", help="Run interactive mode")
    args = parser.parse_args()

    if args.check:
        print_report(args.check, analyze_password(args.check))
    elif args.generate is not None:
        pwd = generate_password(args.generate)
        print(f"Generated password: {pwd}")
        print_report(pwd, analyze_password(pwd))
    elif args.passphrase is not None:
        print(f"Generated passphrase: {generate_passphrase(args.passphrase)}")
    elif args.interactive:
        try:
            pwd = input("Enter a password to analyze: ")
        except (KeyboardInterrupt, EOFError):
            sys.exit(0)
        print_report(pwd, analyze_password(pwd))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
