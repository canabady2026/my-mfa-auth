#!/usr/bin/env python3
"""
Decode TOTP QR code images (Google Authenticator "export accounts" batches,
or plain single-account otpauth:// QR codes) and append them to a local
.env file in TOTP_<n>_* format consumed by totp_menu.py.

This script never commits or uploads anything - it only writes to your
local .env file. Run it locally, then delete the source images if you
don't want them lingering on disk.

Requires: opencv-python-headless (for QR decoding)
    pip install -r requirements.txt

Usage:
    python3 import_qr.py path/to/qr1.jpg path/to/qr2.jpg ...
"""

import base64
import os
import sys
import urllib.parse

try:
    import cv2
except ImportError:
    print("Missing dependency 'opencv-python-headless'. Install with:")
    print("    pip install -r requirements.txt")
    sys.exit(1)

ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")


# ---- otpauth-migration:// protobuf parsing -------------------------------

def read_varint(data, index):
    result = 0
    shift = 0
    while True:
        b = data[index]
        index += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, index


def parse_otp_parameters(chunk):
    fields = {"secret": b"", "name": "", "issuer": "", "algorithm": 0, "digits": 0, "type": 0}
    i = 0
    while i < len(chunk):
        tag, i = read_varint(chunk, i)
        field_num = tag >> 3
        wire_type = tag & 0x07
        if wire_type == 0:
            value, i = read_varint(chunk, i)
        elif wire_type == 2:
            length, i = read_varint(chunk, i)
            value = chunk[i:i + length]
            i += length
        else:
            raise ValueError(f"Unsupported wire type {wire_type}")
        if field_num == 1:
            fields["secret"] = value
        elif field_num == 2:
            fields["name"] = value.decode("utf-8", errors="replace")
        elif field_num == 3:
            fields["issuer"] = value.decode("utf-8", errors="replace")
        elif field_num == 4:
            fields["algorithm"] = value
        elif field_num == 5:
            fields["digits"] = value
        elif field_num == 6:
            fields["type"] = value
    return fields


def parse_migration_payload(raw):
    entries = []
    i = 0
    while i < len(raw):
        tag, i = read_varint(raw, i)
        field_num = tag >> 3
        wire_type = tag & 0x07
        if field_num == 1 and wire_type == 2:
            length, i = read_varint(raw, i)
            chunk = raw[i:i + length]
            i += length
            entries.append(parse_otp_parameters(chunk))
        elif wire_type == 2:
            length, i = read_varint(raw, i)
            i += length
        elif wire_type == 0:
            _, i = read_varint(raw, i)
        else:
            raise ValueError(f"Unsupported wire type {wire_type} at top level")
    return entries


ALGO_MAP = {0: "SHA1", 1: "SHA1", 2: "SHA256", 3: "SHA512", 4: "MD5"}


def entries_from_migration_url(url):
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    data_b64 = qs.get("data", [None])[0]
    if not data_b64:
        return []
    raw = base64.b64decode(data_b64)
    out = []
    for e in parse_migration_payload(raw):
        secret_b32 = base64.b32encode(e["secret"]).decode("ascii").rstrip("=")
        digits = 8 if e["digits"] == 2 else 6
        algo = ALGO_MAP.get(e["algorithm"], "SHA1")
        label = f"{e['issuer']}: {e['name']}" if e["issuer"] else e["name"]
        out.append({"label": label, "secret": secret_b32, "digits": digits, "period": 30, "algo": algo})
    return out


def entries_from_otpauth_url(url):
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    secret = qs.get("secret", [None])[0]
    if not secret:
        return []
    label_path = urllib.parse.unquote(parsed.path).lstrip("/")
    issuer = qs.get("issuer", [None])[0]
    label = f"{issuer}: {label_path}" if issuer and issuer not in label_path else label_path
    digits = int(qs.get("digits", ["6"])[0])
    period = int(qs.get("period", ["30"])[0])
    algo = qs.get("algorithm", ["SHA1"])[0].upper()
    return [{"label": label, "secret": secret, "digits": digits, "period": period, "algo": algo}]


def entries_from_url(url):
    if url.startswith("otpauth-migration://"):
        return entries_from_migration_url(url)
    if url.startswith("otpauth://"):
        return entries_from_otpauth_url(url)
    print(f"  Unrecognized QR content (not otpauth/otpauth-migration): {url[:60]}...")
    return []


# ---- QR image decoding ----------------------------------------------------

def decode_qr(path):
    """Try progressively harder to decode a QR code from an image file."""
    img = cv2.imread(path)
    if img is None:
        return None
    detector = cv2.QRCodeDetector()

    data, _, _ = detector.detectAndDecode(img)
    if data:
        return data

    h, w = img.shape[:2]
    crop_boxes = [
        (0.0, 1.0, 0.0, 1.0),
        (0.45, 0.95, 0.10, 0.90),
        (0.50, 0.92, 0.15, 0.85),
        (0.55, 0.90, 0.20, 0.80),
    ]
    for (y0, y1, x0, x1) in crop_boxes:
        crop = img[int(h * y0):int(h * y1), int(w * x0):int(w * x1)]
        for scale in (2, 3, 5, 8, 10):
            big = cv2.resize(crop, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)
            gray = cv2.cvtColor(big, cv2.COLOR_BGR2GRAY)
            data, _, _ = detector.detectAndDecode(gray)
            if data:
                return data
    return None


# ---- .env writing ----------------------------------------------------------

def load_existing_env():
    values = {}
    if os.path.exists(ENV_PATH):
        with open(ENV_PATH, "r") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                values[k.strip()] = v.strip().strip('"')
    return values


def append_entries(new_entries):
    existing = load_existing_env()
    count = int(existing.get("TOTP_COUNT", "0") or 0)
    existing_secrets = {existing.get(f"TOTP_{i}_SECRET") for i in range(1, count + 1)}

    lines = []
    added = 0
    for e in new_entries:
        if e["secret"] in existing_secrets:
            print(f"  Skipping duplicate (already in .env): {e['label']}")
            continue
        count += 1
        added += 1
        existing_secrets.add(e["secret"])
        lines.append(f'TOTP_{count}_LABEL="{e["label"]}"')
        lines.append(f'TOTP_{count}_SECRET={e["secret"]}')
        lines.append(f'TOTP_{count}_DIGITS={e["digits"]}')
        lines.append(f'TOTP_{count}_PERIOD={e["period"]}')
        lines.append(f'TOTP_{count}_ALGO={e["algo"]}')
        print(f"  Added #{count}: {e['label']}")

    if added == 0:
        return

    if not os.path.exists(ENV_PATH):
        header = "# TOTP secrets - DO NOT COMMIT THIS FILE. See .env.example for the format.\n"
        body = header + "\n".join(lines) + "\n"
        with open(ENV_PATH, "w") as fh:
            fh.write(f"TOTP_COUNT={count}\n")
            fh.write(body)
    else:
        with open(ENV_PATH, "r") as fh:
            existing_lines = fh.readlines()
        with open(ENV_PATH, "w") as fh:
            wrote_count = False
            for line in existing_lines:
                if line.startswith("TOTP_COUNT="):
                    fh.write(f"TOTP_COUNT={count}\n")
                    wrote_count = True
                else:
                    fh.write(line)
            if not wrote_count:
                fh.write(f"TOTP_COUNT={count}\n")
            fh.write("\n".join(lines) + "\n")

    try:
        os.chmod(ENV_PATH, 0o600)
    except OSError:
        pass


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    all_entries = []
    for path in sys.argv[1:]:
        print(f"Decoding {path} ...")
        url = decode_qr(path)
        if not url:
            print(f"  Could not decode a QR code from {path}")
            continue
        entries = entries_from_url(url)
        print(f"  Found {len(entries)} account(s)")
        all_entries.extend(entries)

    if not all_entries:
        print("No accounts decoded.")
        sys.exit(1)

    append_entries(all_entries)
    print(f"\nDone. Secrets stored in {ENV_PATH} (never commit this file).")


if __name__ == "__main__":
    main()
