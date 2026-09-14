"""User-scope heartbeat. No secrets. No console."""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "runtime" / "Lib" / "site-packages"))
local = os.environ.get("LOCALAPPDATA", "").strip() or str(Path.home() / "AppData" / "Local")
os.environ.setdefault("HERMES_CORE_HOME", str(Path(local) / "HermesCore"))


def main() -> int:
    logdir = Path(os.environ["HERMES_CORE_HOME"]) / "Logs"
    logdir.mkdir(parents=True, exist_ok=True)
    rec = {
        "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event": "background",
        "version": "0.1.2",
        "status": "fail",
    }
    try:
        from hermes_core.identity import fingerprint, load_or_create_identity, public_key_text

        key, _meta = load_or_create_identity()
        rec["fingerprint"] = fingerprint(public_key_text(key.public_key()))
        rec["status"] = "ok"
    except Exception as exc:
        rec["error"] = type(exc).__name__
    path = logdir / "heartbeat.jsonl"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(rec, sort_keys=True) + "\n")
    return 0 if rec["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
