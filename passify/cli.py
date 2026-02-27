import json
import os
from getpass import getpass
from pathlib import Path
from typing import Any, Dict

from .crypto import encrypt


def default_vault_path() -> Path:
    home = Path(os.path.expanduser("~"))
    vault_dir = home / ".passify"
    vault_dir.mkdir(parents=True, exist_ok=True)
    return vault_dir / "vault.json"


def prompt_new_master_password() -> str:
    while True:
        pw1 = getpass("Create a new master password: ")
        if not pw1:
            print("Master password cannot be empty.")
            continue

        pw2 = getpass("Confirm master password: ")
        if pw1 != pw2:
            print("Passwords do not match. Please try again.\n")
            continue

        if len(pw1) < 12:
            print(
                "Warning: Using at least 12 characters is recommended for security."
            )
            confirm = input("Use this shorter password anyway? [y/N]: ").strip().lower()
            if confirm != "y":
                print("Okay, let's try again.\n")
                continue

        return pw1


def create_empty_vault(password: str, path: Path) -> None:
    initial_data: Dict[str, Any] = {
        "version": 1,
        "items": [],
        "notes": [],
    }
    plaintext = json.dumps(initial_data, separators=(",", ":")).encode("utf-8")
    encrypted_blob = encrypt(password, plaintext)

    with path.open("w", encoding="utf-8") as f:
        json.dump(encrypted_blob, f, separators=(",", ":"))
        f.write("\n")


def main() -> None:
    vault_path = default_vault_path()

    if not vault_path.exists():
        print("No vault found. Let's create one now.\n")
        password = prompt_new_master_password()
        create_empty_vault(password, vault_path)
        print(f"\nVault created at {vault_path}")
        print("Keep your master password safe – it cannot be recovered if lost.")
        return

    print(f"Vault already exists at {vault_path}.")
    print("Future versions will let you unlock and manage entries here.")


if __name__ == "__main__":
    main()

