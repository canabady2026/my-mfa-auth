#!/usr/bin/env python3
"""
Interactive menu that shows live TOTP codes for accounts stored in .env.

Secrets are never hardcoded here - they are loaded from a local .env file
(see .env.example for the format) which is gitignored and never committed.

Usage:
    python3 totp_menu.py
"""

import base64
import hashlib
import hmac
import os
import re
import select
import struct
import sys
import time

ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")

_B32 = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
_ALGOS = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
}


def load_env_file(path):
    """Minimal .env parser: KEY=VALUE per line, optional quotes, # comments."""
    values = {}
    if not os.path.exists(path):
        return values
    with open(path, "r") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip()
            if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
                val = val[1:-1]
            values[key] = val
    return values


def load_accounts():
    env = load_env_file(ENV_PATH)
    env.update(os.environ)  # real environment variables win over .env file

    count = int(env.get("TOTP_COUNT", "0") or 0)
    accounts = []
    for i in range(1, count + 1):
        secret = env.get(f"TOTP_{i}_SECRET")
        if not secret:
            continue
        label = env.get(f"TOTP_{i}_LABEL", f"Account {i}")
        digits = int(env.get(f"TOTP_{i}_DIGITS", "6") or 6)
        period = int(env.get(f"TOTP_{i}_PERIOD", "30") or 30)
        algo = env.get(f"TOTP_{i}_ALGO", "SHA1").upper()
        accounts.append(
            {"label": label, "secret": secret, "digits": digits, "period": period, "algo": algo}
        )
    return accounts


def totp_code(secret_b32, digits=6, period=30, algo="SHA1", ts=None):
    clean = "".join(c for c in secret_b32.upper() if c in _B32)
    key = base64.b32decode(clean + "=" * (-len(clean) % 8))
    ts = int(time.time()) if ts is None else ts
    counter = struct.pack(">Q", ts // period)
    digestmod = _ALGOS.get(algo, hashlib.sha1)
    digest = hmac.new(key, counter, digestmod).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def seconds_remaining(period=30):
    return period - int(time.time()) % period


def key_pressed():
    """Non-blocking check for an Enter/keypress on stdin (POSIX only)."""
    ready, _, _ = select.select([sys.stdin], [], [], 0)
    if ready:
        sys.stdin.readline()
        return True
    return False


def show_menu(accounts):
    print("\n=== TOTP Accounts ===")
    for i, acc in enumerate(accounts, 1):
        print(f"  {i}. {acc['label']}")
    print("  q. Quit")


def show_code_loop(acc):
    print(f"\nShowing TOTP for: {acc['label']}")
    print("(press Enter to return to the menu)\n")
    last_code = None
    while True:
        code = totp_code(acc["secret"], acc["digits"], acc["period"], acc["algo"])
        remaining = seconds_remaining(acc["period"])
        if code != last_code:
            print()
            last_code = code
        bar = "#" * remaining + "-" * (acc["period"] - remaining)
        sys.stdout.write(f"\r  Code: {code}   expires in {remaining:2d}s  [{bar}]  ")
        sys.stdout.flush()
        if key_pressed():
            print()
            return
        time.sleep(1)


def main():
    accounts = load_accounts()
    if not accounts:
        print(f"No accounts found. Populate {ENV_PATH} (see .env.example) "
              f"or run import_qr.py against your exported QR codes first.")
        sys.exit(1)

    while True:
        show_menu(accounts)
        choice = input("\nSelect an account: ").strip().lower()
        if choice in ("q", "quit", "exit"):
            break
        if not re.fullmatch(r"\d+", choice):
            print("Invalid choice.")
            continue
        idx = int(choice)
        if not (1 <= idx <= len(accounts)):
            print("Invalid choice.")
            continue
        show_code_loop(accounts[idx - 1])


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nBye.")
