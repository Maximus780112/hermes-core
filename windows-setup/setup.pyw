"""Hermès Core Setup — Windows, pythonw, no console. User-level only."""
from __future__ import annotations

import json
import os
import platform
import ssl
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

APP_VERSION = "0.1.2"
PAIR_URL_DEFAULT = "https://mark-h370hd3.tail812275.ts.net/hermes/v1/pair"


def _msg(text: str, title: str = "Hermès Core", flags: int = 0) -> int:
    try:
        import ctypes

        return int(ctypes.windll.user32.MessageBoxW(None, text, title, flags))
    except Exception:
        print(text)
        return 1


def _localapp() -> Path:
    local = os.environ.get("LOCALAPPDATA", "").strip()
    if not local:
        local = str(Path.home() / "AppData" / "Local")
    return Path(local) / "HermesCore"


def _runtime_src() -> Path:
    return Path(__file__).resolve().parent / "runtime"


def write_report(payload: dict) -> Path:
    support = _localapp()
    logs = support / "Logs"
    logs.mkdir(parents=True, exist_ok=True)
    path = logs / "setup-report.json"
    payload = dict(payload)
    payload["written_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path


def run_setup() -> dict:
    checks: dict[str, str] = {}
    report: dict = {
        "app_version": APP_VERSION,
        "windows_version": platform.version(),
        "architecture": platform.machine(),
        "python": sys.version.split()[0],
        "checks": checks,
        "error": None,
        "status": "FAIL",
    }
    if os.name != "nt":
        report["error"] = "Cette application fonctionne uniquement sur Windows."
        return report
    checks["system"] = "PASS"

    support = _localapp()
    runtime = support / "runtime"
    src = _runtime_src()
    if not src.is_dir():
        report["error"] = "Runtime embarqué introuvable."
        return report
    runtime.mkdir(parents=True, exist_ok=True)
    # runtime is already the python tree next to setup; use it in-place
    sys.path.insert(0, str(src / "Lib" / "site-packages"))
    try:
        import hermes_core  # noqa: F401
        from hermes_core.identity import load_or_create_identity, public_key_text, fingerprint
        from hermes_core.identity_store import default_core_home, IDENTITY_NAME
    except Exception as exc:
        report["error"] = f"Installation du Core impossible ({type(exc).__name__})"
        report["detail"] = str(exc)
        return report
    checks["install"] = "PASS"

    os.environ.setdefault("HERMES_CORE_HOME", str(support))
    try:
        key, meta = load_or_create_identity()
        pub = public_key_text(key.public_key())
        report["public_fingerprint"] = fingerprint(pub)
        report["identity_path"] = str(default_core_home() / IDENTITY_NAME)
    except Exception as exc:
        report["error"] = "Création de l'identité impossible."
        report["detail"] = str(exc)
        return report
    checks["identity"] = "PASS"

    ident = Path(report["identity_path"])
    raw = ident.read_text(encoding="utf-8")
    if "BEGIN PRIVATE KEY" in raw or "private_key\"" in raw and "private_key_protected" not in raw:
        report["error"] = "Clé privée en clair détectée."
        return report
    data = json.loads(raw)
    if data.get("private_key"):
        report["error"] = "Clé privée en clair détectée."
        return report
    if not data.get("private_key_protected"):
        report["error"] = "Secret DPAPI absent."
        return report
    if data.get("secret_backend") != "dpapi":
        report["error"] = "Backend secret inattendu."
        return report
    if "token" in data or "pairing_token" in data:
        report["error"] = "Jeton de pairing persisté."
        return report
    checks["dpapi"] = "PASS"
    checks["no_plaintext"] = "PASS"
    checks["no_token"] = "PASS"

    # reload roundtrip
    try:
        key2, _ = load_or_create_identity()
        if public_key_text(key2.public_key()) != pub:
            report["error"] = "L'identité n'est pas stable."
            return report
    except Exception as exc:
        report["error"] = "Lecture DPAPI impossible."
        report["detail"] = str(exc)
        return report
    checks["dpapi_roundtrip"] = "PASS"

    ctx = ssl.create_default_context()
    try:
        import urllib.request

        req = urllib.request.Request(
            "https://mark-h370hd3.tail812275.ts.net/hermes/downloads/hermes_core-0.1.2-py3-none-any.whl",
            method="HEAD",
        )
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            report["tls_status"] = resp.status
        checks["tls"] = "PASS"
    except Exception as exc:
        report["error"] = "Vérification TLS impossible."
        report["detail"] = str(exc)
        return report

    report["status"] = "READY"
    report["install_scope"] = "user"
    report["identity_backend"] = "WindowsIdentityStore"
    return report


def main() -> int:
    silent = os.environ.get("HERMES_SETUP_SILENT", "").strip() in {"1", "true", "TRUE", "yes"}
    if not silent:
        _msg(
            "Hermès Core\n───────────\nInstallation et vérification de votre Hermès privé.",
            flags=0x40,
        )
    try:
        report = run_setup()
    except Exception:
        report = {"status": "FAIL", "error": "Erreur interne.", "detail": traceback.format_exc()}
    path = write_report(report)
    if report.get("status") == "READY":
        if not silent:
            _msg("Hermès Core est prêt\n\nRapport : " + str(path), flags=0x40)
        return 0
    err = report.get("error") or "Installation impossible"
    if not silent:
        _msg("Installation impossible\n" + str(err), flags=0x10)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
