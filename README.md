# my-mfa-auth

A small local TOTP (2FA) tool: import your authenticator QR exports once,
then pull up any account's live 6-digit code from a menu.

Secrets live only in a local `.env` file, which is gitignored and never
committed. No QR images or secrets are ever stored in this repository.

## Setup

```bash
pip install -r requirements.txt
```

## 1. Import accounts from a QR code image

Works with:
- Google Authenticator's "Export accounts" QR codes (`otpauth-migration://`,
  can contain multiple accounts per image)
- Standard single-account `otpauth://` QR codes (e.g. from most other
  services/apps)

```bash
python3 import_qr.py path/to/qr-export-1.jpg path/to/qr-export-2.jpg
```

This decodes each image and appends the accounts found to `.env` in your
project directory (created if it doesn't exist). Duplicate secrets are
skipped automatically. Delete the source images afterwards if you don't
want them on disk - they are gitignored either way.

You can also hand-edit `.env` directly; see `.env.example` for the format.

## 2. Show TOTP codes

```bash
python3 totp_menu.py
```

You'll get a numbered menu of every account label found in `.env`. Pick a
number to see that account's live code, auto-refreshing with a countdown
until the code rotates. Press Enter to return to the menu, or `q` to quit.

## Security notes

- `.env` contains raw TOTP secrets - treat it exactly like a password file.
  It is listed in `.gitignore` and must never be committed or pushed.
- QR code images (`*.jpg`, `*.png`, etc.) are also gitignored for the same
  reason - they encode the same secrets.
- This is a personal/local convenience tool, not a hardened secrets vault.
  For anything beyond casual personal use, consider a dedicated password
  manager with TOTP support.
