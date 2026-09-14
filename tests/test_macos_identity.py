from __future__ import annotations

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
    MACOS_BACKEND,
    MacOSIdentityStore,
    macos_identity_home,
    set_store,
)


class FakeKeychain:
    def __init__(self) -> None:
        self.data: dict[tuple[str, str], bytes] = {}

    def put(self, service: str, account: str, secret: bytes) -> None:
        self.data[(service, account)] = secret

    def get(self, service: str, account: str) -> bytes:
        try:
            return self.data[(service, account)]
        except KeyError as exc:
            raise IdentityError("identity_unprotect_failed") from exc


class MacOSIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "Library" / "Application Support" / "HermesCore" / "identity.json"
        self.backend = FakeKeychain()
        set_store(MacOSIdentityStore(self.backend))

    def tearDown(self) -> None:
        set_store(None)
        self.tmp.cleanup()

    def test_roundtrip_without_plaintext_key(self) -> None:
        key, _ = load_or_create_identity(self.path)
        raw = self.path.read_text(encoding="utf-8")
        payload = json.loads(raw)
        self.assertNotIn("private_key", payload)
        self.assertNotIn("BEGIN PRIVATE KEY", raw)
        self.assertEqual(MACOS_BACKEND, payload["secret_backend"])
        self.assertIn("keychain_account", payload)
        key2, meta = load_identity(self.path)
        self.assertEqual(public_key_text(key.public_key()), public_key_text(key2.public_key()))
        self.assertEqual(MACOS_BACKEND, meta["secret_backend"])

    def test_token_not_persisted(self) -> None:
        key = Ed25519PrivateKey.generate()
        save_identity(self.path, key, extra={"token": "secret-token", "device_id": "d-mac"})
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        dumped = json.dumps(payload)
        self.assertNotIn("secret-token", dumped)
        self.assertNotIn("token", payload)
        self.assertEqual("d-mac", payload["device_id"])

    def test_pair_success_meta(self) -> None:
        key = Ed25519PrivateKey.generate()
        save_identity(self.path, key)
        save_identity(
            self.path,
            key,
            extra={
                "device_id": "device-mac-test",
                "protocol_version": "1",
                "pairing_endpoint": "https://example.test/hermes/v1/pair",
                "token": "must-not-store",
            },
        )
        _key, meta = load_identity(self.path)
        self.assertEqual("device-mac-test", meta["device_id"])
        self.assertNotIn("token", meta)

    def test_failed_pair_no_device(self) -> None:
        _key, meta = load_or_create_identity(self.path)
        self.assertNotIn("device_id", meta)

    def test_missing_keychain_item_fail_closed(self) -> None:
        load_or_create_identity(self.path)
        self.backend.data.clear()
        with self.assertRaises(IdentityError) as ctx:
            load_identity(self.path)
        self.assertEqual("identity_unprotect_failed", str(ctx.exception))

    def test_corrupt_account_fail_closed(self) -> None:
        load_or_create_identity(self.path)
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        payload["keychain_account"] = "identity-deadbeef"
        self.path.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaises(IdentityError):
            load_identity(self.path)

    def test_plaintext_json_rejected(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"identity_type": "hermes-core", "private_key": "BEGIN"}), encoding="utf-8")
        with self.assertRaises(IdentityError) as ctx:
            load_identity(self.path)
        self.assertEqual("insecure_identity_plaintext", str(ctx.exception))

    def test_macos_home_path(self) -> None:
        self.assertEqual(
            "/Users/leo/Library/Application Support/HermesCore",
            macos_identity_home("/Users/leo"),
        )


if __name__ == "__main__":
    unittest.main()
