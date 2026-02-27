import json
import os
from getpass import getpass
from pathlib import Path
from typing import Any, Dict, Tuple

from cryptography.exceptions import InvalidTag

from .crypto import encrypt, decrypt


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


def create_empty_vault(password: str, path: Path) -> Dict[str, Any]:
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

    return initial_data


def load_encrypted_blob(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def unlock_vault(path: Path, max_attempts: int = 3) -> Tuple[Dict[str, Any], str]:
    blob = load_encrypted_blob(path)

    for attempt in range(1, max_attempts + 1):
        password = getpass("Master password: ")
        try:
            plaintext = decrypt(password, blob)
            data = json.loads(plaintext.decode("utf-8"))
            if "items" not in data:
                data.setdefault("items", [])
            if "notes" not in data:
                data.setdefault("notes", [])
            return data, password
        except InvalidTag:
            print("Incorrect master password.")
            if attempt < max_attempts:
                print("Please try again.\n")
            else:
                print("Too many failed attempts. Exiting.")
                raise SystemExit(1)

    raise SystemExit(1)


def save_vault(data: Dict[str, Any], password: str, path: Path) -> None:
    plaintext = json.dumps(data, separators=(",", ":")).encode("utf-8")
    encrypted_blob = encrypt(password, plaintext)
    with path.open("w", encoding="utf-8") as f:
        json.dump(encrypted_blob, f, separators=(",", ":"))
        f.write("\n")


def cmd_list(vault: Dict[str, Any]) -> None:
    items = vault.get("items", [])

    if not items:
        print("No password entries stored yet.")
        return

    for idx, item in enumerate(items):
        name = item.get("name", f"entry-{idx}")
        username = item.get("username", "")
        print(f"[{idx}] {name}" + (f" (user: {username})" if username else ""))


def cmd_add(vault: Dict[str, Any], password: str, vault_path: Path) -> None:
    print("Adding a new password entry.")
    name = input("Name (e.g. site/app): ").strip()
    if not name:
        print("Name is required.")
        return

    username = input("Username (optional): ").strip()
    secret = getpass("Password/secret: ")
    if not secret:
        print("Password cannot be empty.")
        return

    notes = input("Notes (optional): ").strip()

    items = vault.setdefault("items", [])
    items.append(
        {
            "name": name,
            "username": username,
            "password": secret,
            "notes": notes,
        }
    )

    save_vault(vault, password, vault_path)
    print("Entry added.")


def cmd_remove(vault: Dict[str, Any], password: str, vault_path: Path, index: int) -> None:
    items = vault.get("items", [])

    if index < 0 or index >= len(items):
        print(f"No entry at index {index}.")
        return

    item = items[index]
    name = item.get("name", f"entry-{index}")
    confirm = input(f"Remove entry '{name}' at index {index}? [y/N]: ").strip().lower()
    if confirm != "y":
        print("Aborted.")
        return

    del items[index]
    save_vault(vault, password, vault_path)
    print("Entry removed.")


def cmd_show(vault: Dict[str, Any], index: int) -> None:
    items = vault.get("items", [])

    if index < 0 or index >= len(items):
        print(f"No entry at index {index}.")
        return

    item = items[index]
    print(f"Name     : {item.get('name', '')}")
    print(f"Username : {item.get('username', '')}")
    print(f"Password : {item.get('password', '')}")
    if item.get("notes"):
        print(f"Notes    : {item.get('notes')}")


def interactive_menu(vault_path: Path, vault: Dict[str, Any], password: str) -> None:
    while True:
        print("\nPassify menu")
        print("1) List password entries")
        print("2) Add a password entry")
        print("3) Show a password entry (including secret)")
        print("4) Remove a password entry")
        print("5) Quit")

        choice = input("Select an option [1-5]: ").strip()

        if choice == "1":
            cmd_list(vault)
        elif choice == "2":
            cmd_add(vault, password, vault_path)
        elif choice == "3":
            index_str = input("Entry index to show: ").strip()
            if not index_str.isdigit():
                print("Please enter a numeric index.")
                continue
            cmd_show(vault, int(index_str))
        elif choice == "4":
            index_str = input("Entry index to remove: ").strip()
            if not index_str.isdigit():
                print("Please enter a numeric index.")
                continue
            cmd_remove(vault, password, vault_path, int(index_str))
        elif choice == "5":
            print("Goodbye.")
            break
        else:
            print("Invalid choice, please select 1-5.")


def main(argv=None) -> None:
    vault_path = default_vault_path()

    if not vault_path.exists():
        print("No vault found. Let's create one now.\n")
        password = prompt_new_master_password()
        vault = create_empty_vault(password, vault_path)
        print(f"\nVault created at {vault_path}")
        print("Keep your master password safe – it cannot be recovered if lost.\n")
    else:
        print("Unlocking existing vault.\n")
        vault, password = unlock_vault(vault_path)

    interactive_menu(vault_path, vault, password)


if __name__ == "__main__":
    main()

