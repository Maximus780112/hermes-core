"""TLS pairing client. Token via stdin only — never argv."""

from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request
from typing import Any

from . import PAIRING_PROTOCOL_VERSION
from .identity import public_key_text

MAX_RESPONSE = 8192
DEFAULT_TIMEOUT = 15.0


class PairingClientError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ca = os.environ.get("HERMES_CORE_TLS_CA", "").strip()
    if ca:
        ctx.load_verify_locations(cafile=ca)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def pair_request_body(token: str, public_key: str, protocol_version: str = PAIRING_PROTOCOL_VERSION) -> bytes:
    if not isinstance(token, str) or not token or any(ch.isspace() for ch in token) or "\x00" in token:
        raise PairingClientError("INVALID_OR_EXPIRED_PAIRING")
    if not isinstance(public_key, str) or not public_key or "\x00" in public_key:
        raise PairingClientError("INVALID_PUBLIC_KEY")
    return json.dumps(
        {"protocol_version": protocol_version, "token": token, "public_key": public_key},
        separators=(",", ":"),
    ).encode()


def submit_pair(
    url: str,
    token: str,
    public_key: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    server_hostname: str | None = None,
) -> dict[str, Any]:
    body = pair_request_body(token, public_key)
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Content-Length", str(len(body)))
    ctx = ssl_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read(MAX_RESPONSE + 1)
    except urllib.error.HTTPError as exc:
        raw = exc.read(MAX_RESPONSE + 1)
        return _decode_result(raw, http_error=True)
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", None)
        if isinstance(reason, ssl.SSLError):
            raise PairingClientError("TLS_VALIDATION_FAILED") from exc
        raise PairingClientError("PAIRING_FAILED") from exc
    except ssl.SSLError as exc:
        raise PairingClientError("TLS_VALIDATION_FAILED") from exc
    except OSError as exc:
        raise PairingClientError("PAIRING_FAILED") from exc
    if len(raw) > MAX_RESPONSE:
        raise PairingClientError("PAIRING_FAILED")
    return _decode_result(raw, http_error=False)


def _decode_result(raw: bytes, http_error: bool) -> dict[str, Any]:
    try:
        payload = json.loads(raw.decode())
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PairingClientError("PAIRING_FAILED") from exc
    if not isinstance(payload, dict):
        raise PairingClientError("PAIRING_FAILED")
    if payload.get("ok") is True and isinstance(payload.get("device_id"), str) and payload["device_id"]:
        return {
            "ok": True,
            "device_id": payload["device_id"],
            "protocol_version": str(payload.get("protocol_version") or PAIRING_PROTOCOL_VERSION),
        }
    code = str(payload.get("error") or "PAIRING_FAILED")
    raise PairingClientError(code)


def public_key_for_pair(private_key) -> str:
    return public_key_text(private_key.public_key())
