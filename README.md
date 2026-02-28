# Passify

**Passify** is a 1Password-style password manager for the terminal. Store passwords and notes in a single encrypted vault, unlock with one master password, and manage everything through a keyboard-driven menu.

```
  ____       _        ____      ____      ___      _____     _     _
 |  _ \     / \      / ___|    / ___|     | |      |         \ \ / /
 | |_) |   / _ \     \___ \    \___ \     | |      |___       \   /
 |  __/   | | | |     ___) |    ___) |    | |      |           | |
 |_|      |_| |_|    |____/    |____/     |_|      |           |_|
        ~ keep your secrets safe ~

Passify menu
> 1) Add a password entry
  2) Show a password entry
  3) Remove a password entry
  4) Configuration
  5) Help
  6) Quit

Use Up/Down or k/j to move, Enter to select.

```

---

## Features

- **Encrypted vault** — All data is encrypted with **Scrypt** (key derivation) and **AES-256-GCM** before being written to disk.
- **Master password** — One password unlocks the vault; it is never stored, only used to derive the encryption key.
- **Password entries** — Save name, username, password, and notes per entry. Add, view, and remove entries from the menu.
- **Show & hide** — View a password for a configurable number of seconds, then the screen clears and returns to the menu.
- **Configuration** — Set vault file location, password display time, and change the master password (re-encrypts the vault).
- **Keyboard navigation** — Use **Up/Down** or **k/j** to move, **Enter** to select. Same behavior in all menus.
- **No cloud** — Everything stays on your machine. No account, no sync, no telemetry.

---

## Requirements

- **Python 3.8+**
- **cryptography** (see `requirements.txt`)

---

## Installation

```bash
cd /path/to/passify
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Running Passify

```bash
python -m passify
```

Or use the wrapper script (from the project directory):

```bash
./passify.sh
```

---

## Quick Start

1. **First run** — If no vault exists, you’ll be asked to create a master password (entered twice). A new encrypted vault is created.
2. **Unlock** — On later runs, enter your master password once to open the main menu.
3. **Main menu** — Add entries, show entries (browse and view details), remove entries, open Configuration, view Help, or Quit.

---

## Usage

### Main Menu

| Option | Description |
|--------|-------------|
| **Add a password entry** | Prompts for name, username, password, and notes; saves to the vault. |
| **Show a password entry** | Opens a list of all entries. Move with Up/Down or k/j, Enter to view one. The password is shown for a set number of seconds, then the screen clears and you return to the main menu. |
| **Remove a password entry** | Asks for an entry index (from the list) and, after confirmation, deletes it. |
| **Configuration** | Vault location, password display time (seconds), and change master password. |
| **Help** | Shows this help in the terminal. |
| **Quit** | Exit Passify. |

### Navigation

- **Up / Down** or **k / j** — Move selection.
- **Enter** — Confirm selection.
- **Number keys 1–6** — Jump to that menu option (where applicable).

### Configuration Menu

- **Set vault location** — Path to the encrypted vault file (default: `~/.passify/.vault`). Used the next time you start Passify.
- **Set password display time** — Seconds the password stays visible when viewing an entry (default: 15). Use `0` to show until you leave the screen.
- **Change master password** — Asks for current password, then new password (twice). The vault is re-encrypted with the new key; use the new password from then on.
- **← Back to main menu** — Return without changing anything else.

---

## File Locations

| Path | Purpose |
|------|---------|
| `~/.passify/.vault` | Encrypted vault (default; configurable). |
| `~/.passify/.config.json` | Config: `vault_location`, `password_display_time`. |

---

## Security

- **Encryption** — Vault contents are encrypted with a key derived from your master password using **Scrypt** (n=16384, r=8, p=1) and **AES-256-GCM**.
- **Master password** — Not stored anywhere. If you forget it, the vault cannot be recovered.
- **Passwords in memory** — While the app is open, the decrypted vault and master password are in memory. Quit when you’re done on a shared machine.
- **Display time** — Use Configuration to shorten or disable the “show password” duration so secrets aren’t left on screen.

---

## Command-Line Help

To print a short help and exit without opening the vault:

```bash
python -m passify --help
python -m passify -h
```

---

## License

MIT
