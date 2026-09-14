"""Loopback pairing HTTP frontend. TLS is at ingress. Mutation via Unix writer only."""

from __future__ import annotations

import json
import logging
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger("hermes_core.pairing_frontend")

PROTOCOL_VERSION = 1
MAX_BODY = 2048
MAX_TOKEN_LEN = 256
MAX_PUBKEY_LEN = 128
RATE_WINDOW_S = 60.0
RATE_MAX = 30
GLOBAL_RATE_MAX = 120
REQUEST_TIMEOUT_S = 15
IPC_TIMEOUT_S = 5.0
DEFAULT_BIND = "127.0.0.1"
DEFAULT_PORT = 18791
DEFAULT_SOCKET = Path("/home/assistant/lynq/runtime/m241/lynq-activate.sock")
CONSUME_OP = "consume_pairing"
ALLOWED = frozenset({"protocol_version", "token", "public_key"})
FORBIDDEN = frozenset({"user_id", "device_id", "messaging_address", "realm", "tenant_id", "owner"})
ERROR_MAP = {
    "unknown_token": "INVALID_OR_EXPIRED_PAIRING",
    "invalid_token": "INVALID_OR_EXPIRED_PAIRING",
    "token_expired": "INVALID_OR_EXPIRED_PAIRING",
    "invalid_or_expired_token": "INVALID_OR_EXPIRED_PAIRING",
    "token_consumed": "PAIRING_ALREADY_USED",
    "token_already_consumed": "PAIRING_ALREADY_USED",
    "malformed_public_key": "INVALID_PUBLIC_KEY",
    "invalid_public_key": "INVALID_PUBLIC_KEY",
    "pairing_failed": "PAIRING_FAILED",
}


def _fail(code: str) -> dict[str, Any]:
    return {"ok": False, "error": code, "protocol_version": PROTOCOL_VERSION}


def writer_socket() -> Path:
    raw = os.environ.get("LYNQ_ACTIVATE_SOCKET", "").strip()
    return Path(raw) if raw else DEFAULT_SOCKET


def call_consume(token: str, public_key: str, socket_path: Path | None = None) -> dict[str, Any]:
    body = json.dumps(
        {"op": CONSUME_OP, "token": token, "public_key": public_key},
        separators=(",", ":"),
    ).encode() + b"\n"
    path = str(socket_path or writer_socket())
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(IPC_TIMEOUT_S)
        sock.connect(path)
        sock.sendall(body)
        raw = sock.makefile("rb").readline()
    if not raw:
        return {"ok": False, "error": "PAIRING_FAILED"}
    try:
        payload = json.loads(raw.decode())
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"ok": False, "error": "PAIRING_FAILED"}
    if not isinstance(payload, dict):
        return {"ok": False, "error": "PAIRING_FAILED"}
    return payload


class PairingFrontend:
    def __init__(self, socket_path: Path | None = None) -> None:
        self.socket_path = socket_path or writer_socket()
        self._hits: dict[str, list[float]] = {}
        self._global: list[float] = []
        self._lock = threading.Lock()

    def _rate_ok(self, ip: str) -> bool:
        now = time.monotonic()
        with self._lock:
            self._global = [t for t in self._global if now - t < RATE_WINDOW_S]
            if len(self._global) >= GLOBAL_RATE_MAX:
                return False
            stamps = [t for t in self._hits.get(ip, []) if now - t < RATE_WINDOW_S]
            if len(stamps) >= RATE_MAX:
                self._hits[ip] = stamps
                return False
            stamps.append(now)
            self._hits[ip] = stamps
            self._global.append(now)
            return True

    def handle(self, raw: bytes, ip: str) -> tuple[int, dict[str, Any]]:
        if not self._rate_ok(ip):
            logger.info("event=rate_limited source=%s note=funnel_may_hide_origin", ip)
            return 429, _fail("RATE_LIMITED")
        if len(raw) > MAX_BODY:
            logger.info("event=payload_bound")
            return 400, _fail("PAIRING_FAILED")
        try:
            payload = json.loads(raw.decode())
        except (UnicodeDecodeError, json.JSONDecodeError):
            return 400, _fail("PAIRING_FAILED")
        if not isinstance(payload, dict):
            return 400, _fail("PAIRING_FAILED")
        if FORBIDDEN & payload.keys():
            logger.info("event=forbidden_field")
            return 400, _fail("PAIRING_FAILED")
        if set(payload.keys()) - ALLOWED:
            return 400, _fail("PAIRING_FAILED")
        version = payload.get("protocol_version")
        if version not in (PROTOCOL_VERSION, str(PROTOCOL_VERSION), float(PROTOCOL_VERSION)):
            return 400, _fail("UNSUPPORTED_PROTOCOL")
        token = payload.get("token")
        public_key = payload.get("public_key")
        if not isinstance(token, str) or not token or len(token) > MAX_TOKEN_LEN or "\x00" in token:
            return 400, _fail("INVALID_OR_EXPIRED_PAIRING")
        if not isinstance(public_key, str) or not public_key or len(public_key) > MAX_PUBKEY_LEN:
            return 400, _fail("INVALID_PUBLIC_KEY")
        result = call_consume(token, public_key, self.socket_path)
        if result.get("ok") and isinstance(result.get("device_id"), str) and result["device_id"]:
            logger.info("event=ok")
            return 200, {
                "ok": True,
                "device_id": result["device_id"],
                "protocol_version": PROTOCOL_VERSION,
            }
        err = str(result.get("error") or "")
        mapped = ERROR_MAP.get(err, "PAIRING_FAILED")
        logger.info("event=fail code=%s", mapped)
        return 400, _fail(mapped)


def make_handler(frontend: PairingFrontend) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        timeout = REQUEST_TIMEOUT_S

        def log_message(self, format: str, *args: object) -> None:
            logger.info("http=%s", format % args if args else format)

        def do_POST(self) -> None:
            if urlparse(self.path).path != "/v1/pair":
                self._write(404, _fail("PAIRING_FAILED"))
                return
            try:
                n = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._write(400, _fail("PAIRING_FAILED"))
                return
            if n < 0 or n > MAX_BODY:
                self._write(400, _fail("PAIRING_FAILED"))
                return
            raw = self.rfile.read(n)
            ip = self.client_address[0] if self.client_address else "unknown"
            status, body = frontend.handle(raw, ip)
            self._write(status, body)

        def do_GET(self) -> None:
            self._write(404, _fail("PAIRING_FAILED"))

        def _write(self, status: int, body: dict[str, Any]) -> None:
            data = json.dumps(body, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)

    return Handler


class PairingHTTPServer:
    def __init__(self, frontend: PairingFrontend, host: str = DEFAULT_BIND, port: int = DEFAULT_PORT) -> None:
        self.httpd = ThreadingHTTPServer((host, port), make_handler(frontend))
        self.thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        return int(self.httpd.server_address[1])

    def start(self) -> None:
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    host = os.environ.get("HERMES_PAIRING_BIND", DEFAULT_BIND)
    port = int(os.environ.get("HERMES_PAIRING_PORT", str(DEFAULT_PORT)))
    if host not in {"127.0.0.1", "localhost", "::1"}:
        logger.error("refusing non-loopback bind host=%s", host)
        return 2
    frontend = PairingFrontend()
    server = PairingHTTPServer(frontend, host=host, port=port)
    server.start()
    logger.info("listening bind=%s port=%s socket=%s", host, server.port, frontend.socket_path)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
