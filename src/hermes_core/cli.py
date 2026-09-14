"""hermes-core CLI. Pairing token from stdin, never argv."""

from __future__ import annotations

import argparse
import os
import sys

from . import PAIRING_PROTOCOL_VERSION, __version__
from .identity import fingerprint, load_or_create_identity, public_key_text, save_identity
from .pairing import PairingClientError, public_key_for_pair, submit_pair


def _read_token() -> str:
    if sys.stdin.isatty():
        import getpass

        token = getpass.getpass("pairing code: ")
    else:
        token = sys.stdin.readline()
    token = (token or "").strip()
    if not token:
        raise SystemExit("missing_token")
    return token


def _require_https(url: str) -> str:
    if not url.lower().startswith("https://"):
        raise SystemExit("tls_required")
    return url


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="hermes-core")
    sub = parser.add_subparsers(dest="cmd", required=True)
    pair = sub.add_parser("pair", help="consume a pairing code over TLS")
    pair.add_argument("--url", required=True, help="https pairing endpoint")
    ident = sub.add_parser("identity", help="show public fingerprint")
    args = parser.parse_args(argv)

    if args.cmd == "identity":
        key, _meta = load_or_create_identity()
        pub = public_key_text(key.public_key())
        print(f"fingerprint={fingerprint(pub)} protocol={PAIRING_PROTOCOL_VERSION} version={__version__}")
        return 0
    if args.cmd == "pair":
        url = _require_https(args.url)
        key, _meta = load_or_create_identity()
        token = _read_token()
        try:
            result = submit_pair(url, token, public_key_for_pair(key))
        except PairingClientError as exc:
            print(f"ok=false error={exc.code}", file=sys.stderr)
            return 1
        from .identity import identity_path

        save_identity(
            identity_path(),
            key,
            extra={
                "device_id": result["device_id"],
                "protocol_version": str(result["protocol_version"]),
                "pairing_endpoint": url,
            },
        )
        print(f"ok=true device_id={result['device_id']} protocol_version={result['protocol_version']}")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
