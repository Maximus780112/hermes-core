"""Platform identity stores. One os.name branch, at store selection."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import tempfile
from pathlib import Path, PureWindowsPath
from typing import Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .identity import IdentityError, public_key_text

FORBIDDEN_META = frozenset({"private_key", "token", "pairing_token", "private_key_protected"})
WINDOWS_BACKEND = "dpapi"
WINDOWS_DIRNAME = "HermesCore"
MACOS_BACKEND = "keychain"
MACOS_SERVICE = "ch.hermes.core.identity"
MACOS_DIRNAME = "HermesCore"
IDENTITY_NAME = "identity.json"


class SecretProtector(Protocol):
    def protect(self, plaintext: bytes) -> bytes: ...

    def unprotect(self, blob: bytes) -> bytes: ...


class IdentityStore(Protocol):
    def save(self, path: Path, key: Ed25519PrivateKey, extra: dict[str, str] | None = None) -> None: ...

    def load(self, path: Path) -> tuple[Ed25519PrivateKey, dict[str, str]]: ...


def windows_identity_home(localappdata: str | None = None) -> str:
    if localappdata is None:
        local = os.environ.get("LOCALAPPDATA", "").strip()
    else:
        local = localappdata.strip()
    if not local:
        local = str(Path.home() / "AppData" / "Local")
    return str(PureWindowsPath(local) / WINDOWS_DIRNAME)


def macos_identity_home(home: str | None = None) -> str:
    base = Path(home) if home else Path.home()
    return str(base / "Library" / "Application Support" / MACOS_DIRNAME)


def default_core_home() -> Path:
    if os.name == "nt":
        return Path(windows_identity_home())
    if sys.platform == "darwin":
        return Path(macos_identity_home())
    return Path.home() / ".hermes-core"


def default_store() -> IdentityStore:
    if os.name == "nt":
        return WindowsIdentityStore(DpapiProtector())
    if sys.platform == "darwin":
        from .identity_keychain import SecurityKeychain

        return MacOSIdentityStore(SecurityKeychain())
    return PosixIdentityStore()


_STORE: IdentityStore | None = None


def set_store(store: IdentityStore | None) -> None:
    global _STORE
    _STORE = store


def get_store() -> IdentityStore:
    if _STORE is not None:
        return _STORE
    return default_store()


def _meta_from_extra(extra: dict[str, str] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    if not extra:
        return out
    for k, v in extra.items():
        if k in FORBIDDEN_META:
            continue
        out[str(k)] = str(v)
    return out


def _pem(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _load_pem(pem: bytes) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise IdentityError("identity_not_ed25519")
    return key


def _atomic_write(path: Path, data: bytes, *, posix_mode: bool) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if posix_mode:
        os.chmod(path.parent, 0o700)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".identity.")
    try:
        if posix_mode:
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        if posix_mode:
            os.chmod(path, 0o600)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class PosixIdentityStore:
    def save(self, path: Path, key: Ed25519PrivateKey, extra: dict[str, str] | None = None) -> None:
        pub = public_key_text(key.public_key())
        payload = {
            "identity_type": "hermes-core",
            "public_key": pub,
            "private_key": _pem(key).decode("ascii"),
        }
        payload.update(_meta_from_extra(extra))
        _atomic_write(path, json.dumps(payload, sort_keys=True).encode(), posix_mode=True)

    def load(self, path: Path) -> tuple[Ed25519PrivateKey, dict[str, str]]:
        if not path.is_file():
            raise IdentityError("missing_identity")
        mode = path.stat().st_mode
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise IdentityError("insecure_identity_permissions")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise IdentityError("malformed_identity") from exc
        if not isinstance(payload, dict):
            raise IdentityError("malformed_identity")
        pem = payload.get("private_key")
        if not isinstance(pem, str):
            raise IdentityError("malformed_identity")
        key = _load_pem(pem.encode())
        meta = {str(k): str(v) for k, v in payload.items() if k != "private_key"}
        return key, meta


class DpapiProtector:
    """Windows DPAPI via crypt32. CryptProtectData / CryptUnprotectData."""

    UI_FORBIDDEN = 0x01

    def protect(self, plaintext: bytes) -> bytes:
        return self._crypt(plaintext, encrypt=True)

    def unprotect(self, blob: bytes) -> bytes:
        return self._crypt(blob, encrypt=False)

    def _crypt(self, data: bytes, *, encrypt: bool) -> bytes:
        try:
            import ctypes
            from ctypes import wintypes
        except ImportError as exc:
            raise IdentityError("dpapi_unavailable") from exc
        if os.name != "nt":
            raise IdentityError("dpapi_unavailable")
        try:
            crypt32 = ctypes.windll.crypt32  # type: ignore[attr-defined]
            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        except AttributeError as exc:
            raise IdentityError("dpapi_unavailable") from exc

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

        in_buf = ctypes.create_string_buffer(data, len(data))
        blob_in = DATA_BLOB(len(data), ctypes.cast(in_buf, ctypes.POINTER(ctypes.c_char)))
        blob_out = DATA_BLOB()
        if encrypt:
            ok = crypt32.CryptProtectData(
                ctypes.byref(blob_in),
                None,
                None,
                None,
                None,
                self.UI_FORBIDDEN,
                ctypes.byref(blob_out),
            )
        else:
            ok = crypt32.CryptUnprotectData(
                ctypes.byref(blob_in),
                None,
                None,
                None,
                None,
                self.UI_FORBIDDEN,
                ctypes.byref(blob_out),
            )
        if not ok:
            raise IdentityError("identity_unprotect_failed" if not encrypt else "identity_protect_failed")
        try:
            return ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            if blob_out.pbData:
                kernel32.LocalFree(blob_out.pbData)


class WindowsIdentityStore:
    def __init__(self, protector: SecretProtector) -> None:
        self.protector = protector

    def save(self, path: Path, key: Ed25519PrivateKey, extra: dict[str, str] | None = None) -> None:
        pub = public_key_text(key.public_key())
        blob = self.protector.protect(_pem(key))
        import base64

        payload = {
            "identity_type": "hermes-core",
            "public_key": pub,
            "secret_backend": WINDOWS_BACKEND,
            "private_key_protected": base64.b64encode(blob).decode("ascii"),
        }
        payload.update(_meta_from_extra(extra))
        _atomic_write(path, json.dumps(payload, sort_keys=True).encode(), posix_mode=False)

    def load(self, path: Path) -> tuple[Ed25519PrivateKey, dict[str, str]]:
        if not path.is_file():
            raise IdentityError("missing_identity")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise IdentityError("malformed_identity") from exc
        if not isinstance(payload, dict):
            raise IdentityError("malformed_identity")
        if payload.get("private_key"):
            raise IdentityError("insecure_identity_plaintext")
        protected = payload.get("private_key_protected")
        if not isinstance(protected, str) or not protected:
            raise IdentityError("malformed_identity")
        import base64

        try:
            blob = base64.b64decode(protected, validate=True)
        except Exception as exc:
            raise IdentityError("malformed_identity") from exc
        try:
            pem = self.protector.unprotect(blob)
        except IdentityError:
            raise
        except Exception as exc:
            raise IdentityError("identity_unprotect_failed") from exc
        key = _load_pem(pem)
        meta = {
            str(k): str(v)
            for k, v in payload.items()
            if k not in {"private_key", "private_key_protected"}
        }
        return key, meta


class KeychainBackend(Protocol):
    def put(self, service: str, account: str, secret: bytes) -> None: ...

    def get(self, service: str, account: str) -> bytes: ...


def _account_for(path: Path) -> str:
    digest = hashlib.sha256(str(path).encode("utf-8")).hexdigest()[:24]
    return f"identity-{digest}"


class MacOSIdentityStore:
    def __init__(self, backend: KeychainBackend) -> None:
        self.backend = backend

    def save(self, path: Path, key: Ed25519PrivateKey, extra: dict[str, str] | None = None) -> None:
        account = _account_for(path)
        self.backend.put(MACOS_SERVICE, account, _pem(key))
        pub = public_key_text(key.public_key())
        payload = {
            "identity_type": "hermes-core",
            "public_key": pub,
            "secret_backend": MACOS_BACKEND,
            "keychain_service": MACOS_SERVICE,
            "keychain_account": account,
        }
        payload.update(_meta_from_extra(extra))
        _atomic_write(path, json.dumps(payload, sort_keys=True).encode(), posix_mode=True)

    def load(self, path: Path) -> tuple[Ed25519PrivateKey, dict[str, str]]:
        if not path.is_file():
            raise IdentityError("missing_identity")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise IdentityError("malformed_identity") from exc
        if not isinstance(payload, dict):
            raise IdentityError("malformed_identity")
        if payload.get("private_key"):
            raise IdentityError("insecure_identity_plaintext")
        if payload.get("secret_backend") != MACOS_BACKEND:
            raise IdentityError("malformed_identity")
        service = payload.get("keychain_service")
        account = payload.get("keychain_account")
        if not isinstance(service, str) or not isinstance(account, str) or not account:
            raise IdentityError("malformed_identity")
        try:
            pem = self.backend.get(service, account)
        except IdentityError:
            raise
        except Exception as exc:
            raise IdentityError("identity_unprotect_failed") from exc
        key = _load_pem(pem)
        meta = {str(k): str(v) for k, v in payload.items() if k not in FORBIDDEN_META}
        return key, meta
