import json
import os
import sys
import time
from getpass import getpass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidTag

from .crypto import encrypt, decrypt


DEFAULT_VAULT_PATH = "~/.passify/.vault"
DEFAULT_PASSWORD_DISPLAY_SECONDS = 15


def _get_key_unix() -> Optional[str]:
    """Read a single key on Unix; returns 'up', 'down', 'enter', or the character."""
    import termios
    import tty
    fd = sys.stdin.fileno()
    try:
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1)
            if ch == "\x1b":
                sys.stdin.read(1)  # [
                c = sys.stdin.read(1)
                if c == "A":
                    return "up"
                if c == "B":
                    return "down"
            if ch in ("\r", "\n"):
                return "enter"
            return ch
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
    except (termios.error, OSError):
        return None


def _get_key_win() -> Optional[str]:
    """Read a single key on Windows; returns 'up', 'down', 'enter', or the character."""
    try:
        import msvcrt
    except ImportError:
        return None
    while True:
        if msvcrt.kbhit():
            break
        time.sleep(0.02)
    ch = msvcrt.getch()
    if ch in (b"\r", b"\n"):
        return "enter"
    if ch == b"\xe0" or ch == b"\x00":
        ext = msvcrt.getch()
        if ext == b"H":
            return "up"
        if ext == b"P":
            return "down"
    try:
        return ch.decode(sys.stdin.encoding or "utf-8", errors="replace")
    except Exception:
        return None


def get_key() -> Optional[str]:
    """Read one keypress; returns 'up', 'down', 'enter', or the key character."""
    if os.name == "nt":
        return _get_key_win()
    return _get_key_unix()


def draw_main_menu(selected: int, options: List[str]) -> None:
    """Print the main menu with the given option selected (0-based index)."""
    print("\nPassify menu")
    for i, label in enumerate(options):
        prefix = "> " if i == selected else "  "
        print(f"{prefix}{label}")
    print("\nUse Up/Down or k/j to move, Enter to select.")


def draw_menu(title: str, options: List[str], selected: int, hint: str = "Use Up/Down or k/j to move, Enter to select.") -> None:
    """Print a menu with title and options; selected is 0-based index."""
    print(f"\n{title}")
    for i, label in enumerate(options):
        prefix = "> " if i == selected else "  "
        print(f"{prefix}{label}")
    print(f"\n{hint}")


def config_path() -> Path:
    home = Path(os.path.expanduser("~"))
    return home / ".passify" / ".config.json"


def ensure_passify_dir() -> Path:
    home = Path(os.path.expanduser("~"))
    vault_dir = home / ".passify"
    vault_dir.mkdir(parents=True, exist_ok=True)
    return vault_dir


def load_config() -> Dict[str, Any]:
    path = config_path()
    if not path.exists():
        return {
            "vault_location": DEFAULT_VAULT_PATH,
            "password_display_time": DEFAULT_PASSWORD_DISPLAY_SECONDS,
        }
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return {
            "vault_location": DEFAULT_VAULT_PATH,
            "password_display_time": DEFAULT_PASSWORD_DISPLAY_SECONDS,
        }
    return {
        "vault_location": data.get("vault_location", DEFAULT_VAULT_PATH),
        "password_display_time": data.get("password_display_time", DEFAULT_PASSWORD_DISPLAY_SECONDS),
    }


def save_config(config: Dict[str, Any]) -> None:
    ensure_passify_dir()
    path = config_path()
    with path.open("w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
        f.write("\n")


def default_vault_path() -> Path:
    ensure_passify_dir()
    config = load_config()
    raw = config.get("vault_location", DEFAULT_VAULT_PATH)
    path = Path(os.path.expanduser(raw))

    # Migrate old default location to .vault if config still points at default
    home = Path(os.path.expanduser("~"))
    legacy_dir = home / ".passify"
    old_path = legacy_dir / "vault.json"
    new_default = legacy_dir / ".vault"

    if path == new_default and not path.exists() and old_path.exists():
        new_default.write_text(old_path.read_text(encoding="utf-8"), encoding="utf-8")
        old_path.unlink()

    return path


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
    path.parent.mkdir(parents=True, exist_ok=True)
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
    path.parent.mkdir(parents=True, exist_ok=True)
    plaintext = json.dumps(data, separators=(",", ":")).encode("utf-8")
    encrypted_blob = encrypt(password, plaintext)
    with path.open("w", encoding="utf-8") as f:
        json.dump(encrypted_blob, f, separators=(",", ":"))
        f.write("\n")


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


def cmd_show(vault: Dict[str, Any], index: int, password_display_seconds: int) -> None:
    items = vault.get("items", [])

    if index < 0 or index >= len(items):
        print(f"No entry at index {index}.")
        return

    item = items[index]
    name = item.get("name", "")
    username = item.get("username", "")
    pwd = item.get("password", "")
    notes = item.get("notes", "")

    print(f"Name     : {name}")
    print(f"Username : {username}")
    print(f"Password : {pwd}")
    if notes:
        print(f"Notes    : {notes}")

    if password_display_seconds > 0:
        remaining = password_display_seconds
        while remaining > 0:
            s = "second" if remaining == 1 else "seconds"
            print(f"\r(Hiding password in {remaining} {s}...)", end="", flush=True)
            time.sleep(1)
            remaining -= 1
        print("\r" + " " * 50, end="", flush=True)
        # Clear screen and move cursor to top (works on Unix and most Windows terminals)
        print("\033[2J\033[H", end="")


def _entry_option_label(item: Dict[str, Any], index: int) -> str:
    name = item.get("name", f"entry-{index}")
    username = item.get("username", "")
    return f"[{index}] {name}" + (f" (user: {username})" if username else "")


def show_entries_menu(vault: Dict[str, Any], password_display_seconds: int) -> None:
    """Show a navigable list of password entries; Enter shows details, Back returns to main menu."""
    items = vault.get("items", [])
    back_label = "← Back to main menu"

    if not items:
        print("\033[2J\033[H", end="")
        print("\nShow a password entry")
        print("\nNo password entries stored yet.")
        return

    options = [_entry_option_label(item, i) for i, item in enumerate(items)] + [back_label]
    selected = 0

    while True:
        print("\033[2J\033[H", end="")
        draw_menu("Show a password entry", options, selected)

        while True:
            key = get_key()
            if key in ("up", "k"):
                selected = (selected - 1) % len(options)
                print("\033[2J\033[H", end="")
                draw_menu("Show a password entry", options, selected)
                continue
            if key in ("down", "j"):
                selected = (selected + 1) % len(options)
                print("\033[2J\033[H", end="")
                draw_menu("Show a password entry", options, selected)
                continue
            if key == "enter":
                break
            if key and key.isdigit() and 0 <= int(key) < len(options):
                selected = int(key)
                break

        if selected == len(options) - 1:
            return

        cmd_show(vault, selected, password_display_seconds)
        return


def config_menu(vault_path: Path, vault: Dict[str, Any], password: str) -> Optional[str]:
    """Returns new master password if changed, else None."""
    options = [
        "Set vault location",
        "Set password display time (seconds)",
        "Change master password",
        "← Back to main menu",
    ]
    selected = 0

    while True:
        config = load_config()
        vault_loc = config.get("vault_location", DEFAULT_VAULT_PATH)
        display_time = config.get("password_display_time", DEFAULT_PASSWORD_DISPLAY_SECONDS)
        title = f"Configuration\n  Vault location   : {vault_loc}\n  Password display : {display_time} seconds"

        print("\033[2J\033[H", end="")
        draw_menu(title, options, selected)

        while True:
            key = get_key()
            if key in ("up", "k"):
                selected = (selected - 1) % len(options)
                config = load_config()
                vault_loc = config.get("vault_location", DEFAULT_VAULT_PATH)
                display_time = config.get("password_display_time", DEFAULT_PASSWORD_DISPLAY_SECONDS)
                title = f"Configuration\n  Vault location   : {vault_loc}\n  Password display : {display_time} seconds"
                print("\033[2J\033[H", end="")
                draw_menu(title, options, selected)
                continue
            if key in ("down", "j"):
                selected = (selected + 1) % len(options)
                config = load_config()
                vault_loc = config.get("vault_location", DEFAULT_VAULT_PATH)
                display_time = config.get("password_display_time", DEFAULT_PASSWORD_DISPLAY_SECONDS)
                title = f"Configuration\n  Vault location   : {vault_loc}\n  Password display : {display_time} seconds"
                print("\033[2J\033[H", end="")
                draw_menu(title, options, selected)
                continue
            if key == "enter":
                break
            if key and key.isdigit() and 1 <= int(key) <= len(options):
                selected = int(key) - 1
                break

        if selected == 0:
            new_loc = input(f"\nVault path [{vault_loc}]: ").strip()
            if new_loc:
                config = load_config()
                config["vault_location"] = new_loc
                save_config(config)
                print("Vault location updated.")
            else:
                print("No change.")
        elif selected == 1:
            raw = input(f"\nPassword display time in seconds [{display_time}]: ").strip()
            if raw:
                try:
                    secs = int(raw)
                    if secs < 0:
                        print("Enter 0 or a positive number.")
                    else:
                        config = load_config()
                        config["password_display_time"] = secs
                        save_config(config)
                        print("Password display time updated.")
                except ValueError:
                    print("Please enter a number.")
            else:
                print("No change.")
        elif selected == 2:
            current = getpass("\nCurrent master password: ")
            if current != password:
                print("Incorrect master password.")
            else:
                new_password = prompt_new_master_password()
                save_vault(vault, new_password, vault_path)
                print("Master password changed. Use the new password next time you open the vault.")
                return new_password
        elif selected == 3:
            break

        if selected != 3:
            input("\nPress Enter to return to configuration...")
    return None


def interactive_menu(vault_path: Path, vault: Dict[str, Any], password: str) -> None:
    options = [
        "1) Add a password entry",
        "2) Show a password entry",
        "3) Remove a password entry",
        "4) Configuration",
        "5) Quit",
    ]
    selected = 0

    while True:
        # Clear and draw menu
        print("\033[2J\033[H", end="")
        draw_main_menu(selected, options)

        # Wait for selection
        while True:
            key = get_key()
            if key in ("up", "k"):
                selected = (selected - 1) % len(options)
                print("\033[2J\033[H", end="")
                draw_main_menu(selected, options)
                continue
            if key in ("down", "j"):
                selected = (selected + 1) % len(options)
                print("\033[2J\033[H", end="")
                draw_main_menu(selected, options)
                continue
            if key == "enter":
                break
            # Number shortcut 1-5
            if key and key.isdigit() and 1 <= int(key) <= len(options):
                selected = int(key) - 1
                break

        # Run selected action
        if selected == 0:
            cmd_add(vault, password, vault_path)
        elif selected == 1:
            config = load_config()
            display_secs = config.get("password_display_time", DEFAULT_PASSWORD_DISPLAY_SECONDS)
            show_entries_menu(vault, display_secs)
        elif selected == 2:
            index_str = input("\nEntry index to remove: ").strip()
            if not index_str.isdigit():
                print("Please enter a numeric index.")
            else:
                cmd_remove(vault, password, vault_path, int(index_str))
        elif selected == 3:
            new_password = config_menu(vault_path, vault, password)
            if new_password is not None:
                password = new_password
        elif selected == 4:
            print("Goodbye.")
            break

        if selected != 4 and selected != 1:
            input("\nPress Enter to return to menu...")


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

