from __future__ import annotations

import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hermes_core.cli import main
from hermes_core.pairing import PairingClientError


class CliPairTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name) / "core-home"
        self._old = os.environ.get("HERMES_CORE_HOME")
        os.environ["HERMES_CORE_HOME"] = str(self.home)

    def tearDown(self) -> None:
        if self._old is None:
            os.environ.pop("HERMES_CORE_HOME", None)
        else:
            os.environ["HERMES_CORE_HOME"] = self._old
        self.tmp.cleanup()

    def test_http_url_rejected(self) -> None:
        with self.assertRaises(SystemExit) as ctx:
            main(["pair", "--url", "http://127.0.0.1:9/v1/pair"])
        self.assertEqual("tls_required", str(ctx.exception))
        self.assertFalse((self.home / "identity.json").exists())

    def test_failed_pair_does_not_mark_paired(self) -> None:
        with mock.patch("hermes_core.cli.submit_pair", side_effect=PairingClientError("PAIRING_FAILED")):
            with mock.patch("hermes_core.cli._read_token", return_value="fixture-token-not-leo"):
                code = main(["pair", "--url", "https://127.0.0.1:9/v1/pair"])
        self.assertEqual(1, code)
        ident = json.loads((self.home / "identity.json").read_text(encoding="utf-8"))
        self.assertNotIn("device_id", ident)
        self.assertNotIn("token", ident)
        self.assertNotIn("pairing_token", ident)
        self.assertEqual(0o600, stat.S_IMODE((self.home / "identity.json").stat().st_mode))

    def test_success_persists_device_not_token(self) -> None:
        result = {"ok": True, "device_id": "device-cli-test", "protocol_version": "1"}
        with mock.patch("hermes_core.cli.submit_pair", return_value=result):
            with mock.patch("hermes_core.cli._read_token", return_value="fixture-token-not-leo"):
                buf = io.StringIO()
                with mock.patch("sys.stdout", buf):
                    code = main(["pair", "--url", "https://example.test/hermes/v1/pair"])
        self.assertEqual(0, code)
        self.assertNotIn("fixture-token", buf.getvalue())
        ident = json.loads((self.home / "identity.json").read_text(encoding="utf-8"))
        self.assertEqual("device-cli-test", ident["device_id"])
        self.assertEqual("1", ident["protocol_version"])
        self.assertEqual("https://example.test/hermes/v1/pair", ident["pairing_endpoint"])
        self.assertNotIn("token", ident)
        self.assertNotIn("pairing_token", ident)
        self.assertIn("private_key", ident)


if __name__ == "__main__":
    unittest.main()
