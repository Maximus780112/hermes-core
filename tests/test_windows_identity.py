from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes_core.identity import (
    IdentityError,
    load_identity,
    load_or_create_identity,
    public_key_text,
    save_identity,
)
from hermes_core.identity_store import (
    WINDOWS_BACKEND,
    WindowsIdentityStore,
    set_store,
    windows_identity_home,
)


class FakeDpapi:
    def __init__(self, user: bytes = b"user-a") -> None:
        self.user = user

    def _mask(self) -> bytes:
        return hashlib.sha256(self.user).digest()

    def protect(self, plaintext: bytes) -> bytes:
        digest = self._mask()
        xored = bytes(b ^ digest[i % 32] for i, b in enumerate(plaintext))
        return b"FAKEDPAPI" + digest[:8] + xored

    def unprotect(self, blob: bytes) -> bytes:
        if not blob.startswith(b"FAKEDPAPI"):
            raise IdentityError("identity_unprotect_failed")
        digest = self._mask()
        if blob[9:17] != digest[:8]:
            raise IdentityError("identity_unprotect_failed")
        body = blob[17:]
        return bytes(b ^ digest[i % 32] for i, b in enumerate(body))


class WindowsIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "HermesCore" / "identity.json"
        self.store = WindowsIdentityStore(FakeDpapi())
        set_store(self.store)

    def tearDown(self) -> None:
        set_store(None)
        self.tmp.cleanup()

    def test_roundtrip_without_plaintext_key(self) -> None:
        key, _ = load_or_create_identity(self.path)
        raw = self.path.read_text(encoding="utf-8")
        payload = json.loads(raw)
        self.assertNotIn("private_key", payload)
        self.assertNotIn("BEGIN PRIVATE KEY", raw)
        self.assertEqual(WINDOWS_BACKEND, payload["secret_backend"])
        self.assertIn("private_key_protected", payload)
        key2, meta = load_identity(self.path)
        self.assertEqual(public_key_text(key.public_key()), public_key_text(key2.public_key()))
        self.assertEqual(WINDOWS_BACKEND, meta["secret_backend"])

    def test_token_not_persisted(self) -> None:
        key = Ed25519PrivateKey.generate()
        save_identity(self.path, key, extra={"token": "secret-token", "pairing_token": "x", "device_id": "d1"})
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        dumped = json.dumps(payload)
        self.assertNotIn("secret-token", dumped)
        self.assertNotIn("token", payload)
        self.assertNotIn("pairing_token", payload)
        self.assertEqual("d1", payload["device_id"])
        self.assertNotIn("private_key", payload)

    def test_pair_success_meta_without_token(self) -> None:
        key = Ed25519PrivateKey.generate()
        save_identity(self.path, key)
        save_identity(
            self.path,
            key,
            extra={
                "device_id": "device-win-test",
                "protocol_version": "1",
                "pairing_endpoint": "https://example.test/hermes/v1/pair",
                "token": "must-not-store",
            },
        )
        _key, meta = load_identity(self.path)
        self.assertEqual("device-win-test", meta["device_id"])
        self.assertNotIn("token", meta)
        self.assertNotIn("must-not-store", json.dumps(meta))

    def test_failed_pair_does_not_write_device(self) -> None:
        key, meta = load_or_create_identity(self.path)
        self.assertNotIn("device_id", meta)
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertNotIn("device_id", payload)

    def test_corrupt_blob_fail_closed(self) -> None:
        load_or_create_identity(self.path)
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        payload["private_key_protected"] = "AAAA"
        self.path.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaises(IdentityError):
            load_identity(self.path)

    def test_plaintext_json_rejected(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps({"identity_type": "hermes-core", "private_key": "BEGIN PRIVATE KEY"}),
            encoding="utf-8",
        )
        with self.assertRaises(IdentityError) as ctx:
            load_identity(self.path)
        self.assertEqual("insecure_identity_plaintext", str(ctx.exception))

    def test_wrong_dpapi_context_fail_closed(self) -> None:
        set_store(WindowsIdentityStore(FakeDpapi(b"user-a")))
        load_or_create_identity(self.path)
        set_store(WindowsIdentityStore(FakeDpapi(b"user-b")))
        with self.assertRaises(IdentityError) as ctx:
            load_identity(self.path)
        self.assertEqual("identity_unprotect_failed", str(ctx.exception))

    def test_windows_home_uses_localappdata(self) -> None:
        self.assertEqual(
            r"C:\Users\leo\AppData\Local\HermesCore",
            windows_identity_home(r"C:\Users\leo\AppData\Local"),
        )


if __name__ == "__main__":
    unittest.main()
