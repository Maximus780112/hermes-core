from __future__ import annotations

import ipaddress
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from lynq.pairing_endpoint import PairingTLSServer
from lynq.pairing_service import PairingService
from lynq.storage import Store

USER = "user-iso-core"
ADDR = "addr-iso-core"
DEVICE = "device-iso-core"


def _mint(dirpath: Path) -> tuple[Path, Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = dirpath / "server.pem"
    key_path = dirpath / "server.key"
    ca_path = dirpath / "ca.pem"
    pem = cert.public_bytes(serialization.Encoding.PEM)
    cert_path.write_bytes(pem)
    ca_path.write_bytes(pem)
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    os.chmod(key_path, 0o600)
    return cert_path, key_path, ca_path


class IsolatedInstallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = Path(tempfile.mkdtemp(prefix="hermes-core-iso-"))
        src = Path("/home/assistant/hermes-core")
        venv = cls.root / "venv"
        subprocess.run(["uv", "venv", str(venv), "--python", "3.11"], check=True, capture_output=True)
        pip = venv / "bin" / "python"
        inst = subprocess.run(
            ["uv", "pip", "install", "--python", str(pip), str(src)],
            capture_output=True,
            text=True,
        )
        if inst.returncode != 0:
            raise RuntimeError(inst.stderr[-800:] or inst.stdout[-800:])
        cls.python = pip
        cls.bin = venv / "bin" / "hermes-core"
        if not cls.bin.is_file():
            raise RuntimeError("hermes-core entrypoint missing after install")

    def _env(self, home: Path, extra: dict[str, str] | None = None) -> dict[str, str]:
        env = {
            k: v
            for k, v in os.environ.items()
            if k not in {"PYTHONPATH", "HERMES_HOME", "VIRTUAL_ENV"}
        }
        env["HOME"] = str(home)
        env["HERMES_CORE_HOME"] = str(home / ".hermes-core")
        env["PATH"] = str(self.bin.parent) + os.pathsep + env.get("PATH", "")
        if extra:
            env.update(extra)
        return env

    def test_help_and_identity_in_clean_home(self) -> None:
        home = self.root / "home-help"
        home.mkdir()
        help_p = subprocess.run(
            [str(self.bin), "--help"],
            capture_output=True,
            text=True,
            env=self._env(home),
        )
        self.assertEqual(0, help_p.returncode, help_p.stderr)
        pair_help = subprocess.run(
            [str(self.bin), "pair", "--help"],
            capture_output=True,
            text=True,
            env=self._env(home),
        )
        self.assertEqual(0, pair_help.returncode, pair_help.stderr)
        ident = subprocess.run(
            [str(self.bin), "identity"],
            capture_output=True,
            text=True,
            env=self._env(home),
        )
        self.assertEqual(0, ident.returncode, ident.stderr)
        path = home / ".hermes-core" / "identity.json"
        self.assertTrue(path.is_file())
        self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
        payload = json.loads(path.read_text(encoding="utf-8"))
        self.assertIn("private_key", payload)
        self.assertNotIn("token", payload)

    def test_http_rejected_by_installed_cli(self) -> None:
        home = self.root / "home-http"
        home.mkdir()
        proc = subprocess.run(
            [str(self.bin), "pair", "--url", "http://127.0.0.1:9/v1/pair"],
            input="not-a-real-token\n",
            capture_output=True,
            text=True,
            env=self._env(home),
        )
        self.assertNotEqual(0, proc.returncode)
        self.assertIn("tls_required", (proc.stderr + proc.stdout).lower() + str(proc.returncode))

    def test_tls_fail_closed_without_ca(self) -> None:
        tmp = self.root / "tls-fail"
        tmp.mkdir()
        cert, key, _ca = _mint(tmp)
        store = Store(tmp / "lynq.sqlite3")
        store.ensure_user(USER, ADDR)
        server = PairingTLSServer(store, str(cert), str(key), host="127.0.0.1", port=0)
        server.start()
        try:
            home = self.root / "home-tls-fail"
            home.mkdir()
            env = self._env(home)
            env.pop("HERMES_CORE_TLS_CA", None)
            proc = subprocess.run(
                [str(self.bin), "pair", "--url", f"https://127.0.0.1:{server.port}/v1/pair"],
                input="fixture-token-not-leo\n",
                capture_output=True,
                text=True,
                env=env,
                timeout=20,
            )
        finally:
            server.close()
            store.close()
        self.assertEqual(1, proc.returncode)
        self.assertIn("TLS_VALIDATION_FAILED", proc.stderr)
        self.assertNotIn("fixture-token-not-leo", proc.stdout + proc.stderr)

    def test_fixture_pair_then_replay(self) -> None:
        tmp = self.root / "tls-ok"
        tmp.mkdir()
        cert, key, ca = _mint(tmp)
        db = tmp / "lynq.sqlite3"
        store = Store(db)
        store.ensure_user(USER, ADDR)
        token = PairingService(store).issue(USER, DEVICE, timedelta(minutes=15))
        server = PairingTLSServer(store, str(cert), str(key), host="127.0.0.1", port=0)
        server.start()
        home = self.root / "home-ok"
        home.mkdir()
        env = self._env(home, {"HERMES_CORE_TLS_CA": str(ca)})
        url = f"https://127.0.0.1:{server.port}/v1/pair"
        try:
            first = subprocess.run(
                [str(self.bin), "pair", "--url", url],
                input=token + "\n",
                capture_output=True,
                text=True,
                env=env,
                timeout=20,
            )
            second = subprocess.run(
                [str(self.bin), "pair", "--url", url],
                input=token + "\n",
                capture_output=True,
                text=True,
                env=env,
                timeout=20,
            )
        finally:
            server.close()
            store.close()
        self.assertEqual(0, first.returncode, first.stderr)
        self.assertIn("ok=true", first.stdout)
        self.assertIn(DEVICE, first.stdout)
        self.assertNotIn(token, first.stdout + first.stderr)
        self.assertEqual(1, second.returncode)
        self.assertIn("PAIRING_ALREADY_USED", second.stderr)
        ident = json.loads((home / ".hermes-core" / "identity.json").read_text(encoding="utf-8"))
        self.assertEqual(DEVICE, ident["device_id"])
        self.assertEqual("1", ident["protocol_version"])
        self.assertEqual(url, ident["pairing_endpoint"])
        self.assertNotIn("token", ident)
        dumped = json.dumps(ident)
        self.assertNotIn(token, dumped)
        self.assertIn("BEGIN PRIVATE KEY", ident["private_key"])
        self.assertEqual(0o600, stat.S_IMODE((home / ".hermes-core" / "identity.json").stat().st_mode))


if __name__ == "__main__":
    unittest.main()
