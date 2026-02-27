# Passify – Encrypted CLI Password Manager

Passify is a simple 1Password‑style password manager implemented as a Python CLI.

On first run, it guides you through creating a master password (entered twice) and generates a **strongly encrypted vault file** to store passwords and secure notes.

## Features (current)

- **Master password setup**: Prompted securely via `getpass`, confirmed twice.
- **Strong encryption**: Vault contents are encrypted using a key derived from your master password with Scrypt and AES‑GCM (via the `cryptography` library).
- **Local vault file**: The encrypted vault is stored under your home directory (e.g. `~/.passify/vault.json`).

## Installation

```bash
cd /Users/danbickford/Src/passify
python -m venv .venv
source .venv/bin/activate  # on Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

Run the CLI via:

```bash
python -m passify
```

On first run, if no vault exists, you will be prompted to create a master password and the encrypted vault will be created. Future commands for adding and retrieving entries can be layered on top of this base.

