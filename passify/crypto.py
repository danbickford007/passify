import base64
import os
from dataclasses import dataclass
from typing import Any, Dict

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend


KDF_SALT_LENGTH = 16
AES_KEY_LENGTH = 32
AES_NONCE_LENGTH = 12


@dataclass
class KdfParams:
    salt: bytes
    n: int = 2**14
    r: int = 8
    p: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "salt": base64.b64encode(self.salt).decode("ascii"),
            "n": self.n,
            "r": self.r,
            "p": self.p,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "KdfParams":
        return cls(
            salt=base64.b64decode(data["salt"]),
            n=int(data["n"]),
            r=int(data["r"]),
            p=int(data["p"]),
        )


def derive_key(password: str, params: KdfParams) -> bytes:
    kdf = Scrypt(
        salt=params.salt,
        length=AES_KEY_LENGTH,
        n=params.n,
        r=params.r,
        p=params.p,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt(password: str, plaintext: bytes) -> Dict[str, Any]:
    params = KdfParams(salt=os.urandom(KDF_SALT_LENGTH))
    key = derive_key(password, params)

    nonce = os.urandom(AES_NONCE_LENGTH)
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=default_backend(),
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return {
        "kdf": params.to_dict(),
        "cipher": {
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "tag": base64.b64encode(encryptor.tag).decode("ascii"),
        },
    }


def decrypt(password: str, blob: Dict[str, Any]) -> bytes:
    params = KdfParams.from_dict(blob["kdf"])
    key = derive_key(password, params)

    cipher_info = blob["cipher"]
    nonce = base64.b64decode(cipher_info["nonce"])
    ciphertext = base64.b64decode(cipher_info["ciphertext"])
    tag = base64.b64decode(cipher_info["tag"])

    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce, tag),
        backend=default_backend(),
    )
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

