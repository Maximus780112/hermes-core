from __future__ import annotations

import json
import os
import ssl
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from datetime import timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes_core.identity import public_key_text
from hermes_core.pairing_frontend import MAX_BODY, PairingFrontend, PairingHTTPServer

from lynq.activation_ipc import ActivationServer
from lynq.activation_server import _handle_operation
from lynq.pairing_service import PairingService
from lynq.storage import Store

USER = "user-fe-test"
ADDR = "addr-fe-test"
DEVICE = "device-fe-aaaa"


class FrontendIpcTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.db = root / "lynq.sqlite3"
        self.sock = root / "activate.sock"
        store = Store(self.db)
        store.ensure_user(USER, ADDR)
        store.close()
        self._old = os.environ.get("LYNQ_SQLITE_PATH")
        os.environ["LYNQ_SQLITE_PATH"] = str(self.db)

        def handle(address: str) -> dict:
            return {"ok": False, "error": "wrong_op"}

        handle.handle_operation = _handle_operation  # type: ignore[attr-defined]
        self.writer = ActivationServer(self.sock, handle, allow_uids={os.getuid()})
        self.writer.start()
        self.http = PairingHTTPServer(PairingFrontend(self.sock), host="127.0.0.1", port=0)
        self.http.start()
        self.url = f"http://127.0.0.1:{self.http.port}/v1/pair"

    def tearDown(self) -> None:
        self.http.close()
        self.writer.close()
        if self._old is None:
            os.environ.pop("LYNQ_SQLITE_PATH", None)
        else:
            os.environ["LYNQ_SQLITE_PATH"] = self._old
        self.tmp.cleanup()

    def _issue(self, device_id: str = DEVICE) -> str:
        store = Store(self.db)
        try:
            return PairingService(store).issue(USER, device_id, timedelta(minutes=15))
        finally:
            store.close()

    def _pub(self) -> str:
        return public_key_text(Ed25519PrivateKey.generate().public_key())

    def _post(self, payload) -> tuple[int, dict]:
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        req = urllib.request.Request(self.url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode())

    def test_valid_pair(self) -> None:
        token = self._issue()
        status, body = self._post({"protocol_version": 1, "token": token, "public_key": self._pub()})
        self.assertEqual(200, status)
        self.assertTrue(body["ok"])
        self.assertEqual(DEVICE, body["device_id"])

    def test_replay(self) -> None:
        token = self._issue()
        self._post({"protocol_version": 1, "token": token, "public_key": self._pub()})
        status, body = self._post({"protocol_version": 1, "token": token, "public_key": self._pub()})
        self.assertEqual(400, status)
        self.assertEqual("PAIRING_ALREADY_USED", body["error"])

    def test_inject_ids(self) -> None:
        token = self._issue("device-inject")
        status, body = self._post(
            {
                "protocol_version": 1,
                "token": token,
                "public_key": self._pub(),
                "user_id": "nope",
            }
        )
        self.assertEqual(400, status)
        self.assertFalse(body["ok"])

    def test_wrong_method_path(self) -> None:
        req = urllib.request.Request(self.url.replace("/v1/pair", "/nope"), data=b"{}", method="POST")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(404, ctx.exception.code)

    def test_concurrent(self) -> None:
        token = self._issue("device-fe-conc")
        wins, fails = [], []

        def run() -> None:
            status, _ = self._post({"protocol_version": 1, "token": token, "public_key": self._pub()})
            (wins if status == 200 else fails).append(1)

        threads = [threading.Thread(target=run) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(1, len(wins))
        self.assertEqual(7, len(fails))


if __name__ == "__main__":
    unittest.main()
