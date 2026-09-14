"""Local Ed25519 device identity. Private key never leaves this process except protected storage."""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

IDENTITY_NAME = "identity.json"


class IdentityError(RuntimeError):
    pass


def core_home() -> Path:
    raw = os.environ.get("HERMES_CORE_HOME", "").strip()
    if raw:
        return Path(raw)
    from .identity_store import default_core_home

    return default_core_home()


def identity_path(home: Path | None = None) -> Path:
    return (home or core_home()) / IDENTITY_NAME


def public_key_text(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def public_key_from_text(value: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(value, validate=True))


def fingerprint(public_b64: str) -> str:
    return hashlib.sha256(public_b64.encode("ascii")).hexdigest()[:16]


def generate_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def save_identity(path: Path, key: Ed25519PrivateKey, extra: dict[str, str] | None = None) -> None:
    from .identity_store import get_store

    get_store().save(path, key, extra)


def load_identity(path: Path) -> tuple[Ed25519PrivateKey, dict[str, str]]:
    from .identity_store import get_store

    return get_store().load(path)


def load_or_create_identity(path: Path | None = None) -> tuple[Ed25519PrivateKey, dict[str, str]]:
    dest = path or identity_path()
    if dest.is_file():
        return load_identity(dest)
    key = generate_private_key()
    save_identity(dest, key)
    return load_identity(dest)
