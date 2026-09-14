from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes_core.identity import (
    IdentityError,
    fingerprint,
    load_identity,
    load_or_create_identity,
    public_key_text,
    save_identity,
)
from hermes_core.pairing import PairingClientError, pair_request_body


class IdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "identity.json"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_generate_and_persist(self) -> None:
        key, meta = load_or_create_identity(self.path)
        pub = public_key_text(key.public_key())
        self.assertTrue(pub)
        self.assertEqual(16, len(fingerprint(pub)))
        mode = self.path.stat().st_mode
        self.assertEqual(0o600, stat.S_IMODE(mode))
        self.assertEqual(0o700, stat.S_IMODE(self.path.parent.stat().st_mode))
        key2, meta2 = load_or_create_identity(self.path)
        self.assertEqual(public_key_text(key.public_key()), public_key_text(key2.public_key()))

    def test_insecure_permissions_rejected(self) -> None:
        key = Ed25519PrivateKey.generate()
        save_identity(self.path, key)
        os.chmod(self.path, 0o644)
        with self.assertRaises(IdentityError):
            load_identity(self.path)

    def test_pair_request_schema(self) -> None:
        pub = public_key_text(Ed25519PrivateKey.generate().public_key())
        body = json.loads(pair_request_body("tokentokentokentokentoken", pub))
        self.assertEqual({"protocol_version", "token", "public_key"}, set(body))
        self.assertEqual("1", body["protocol_version"])
        self.assertNotIn("user_id", body)
        self.assertNotIn("device_id", body)
        self.assertNotIn("messaging_address", body)

    def test_private_key_not_in_request(self) -> None:
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes.__doc__
        pub = public_key_text(key.public_key())
        raw = pair_request_body("abcabcabcabcabcabcabcabcabcabcab", pub)
        self.assertNotIn(b"PRIVATE", raw)
        self.assertNotIn(b"private_key", raw)

    def test_invalid_token_rejected_client_side(self) -> None:
        pub = public_key_text(Ed25519PrivateKey.generate().public_key())
        with self.assertRaises(PairingClientError):
            pair_request_body("has space", pub)
        with self.assertRaises(PairingClientError):
            pair_request_body("", pub)


if __name__ == "__main__":
    unittest.main()
