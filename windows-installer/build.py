#!/usr/bin/env python3
"""Build unsigned HermesCoreSetup-0.1.2.exe from this repository."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import struct
import subprocess
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INST = ROOT / "windows-installer"
CACHE = INST / ".cache"
STAGE = INST / "build/payload"
OUT_DIR = INST / "dist"
MAGIC = b"HERMESCOREZIP1.2"

EMBED_URL = "https://www.python.org/ftp/python/3.12.10/python-3.12.10-embed-amd64.zip"
EMBED_SHA = "4acbed6dd1c744b0376e3b1cf57ce906f9dc9e95e68824584c8099a63025a3c3"
WHEELS = [
    (
        "https://files.pythonhosted.org/packages/32/2e/c9db68a0c4bfa28e310707527c0ee3a2bd254104d2e02e68f3680c197aa4c/cryptography-50.0.0-cp311-abi3-win_amd64.whl",
        "bd1c592e4d5974f0d08d4888e432157adba757c66da0246918e43677fafa2d30",
        "cryptography-50.0.0-cp311-abi3-win_amd64.whl",
    ),
    (
        "https://files.pythonhosted.org/packages/f8/ed/13bd4418627013bec4ed6e54283b1959cf6db888048c7cf4b4c3b5b36002/cffi-2.0.0-cp312-cp312-win_amd64.whl",
        "da68248800ad6320861f129cd9c1bf96ca849a2771a59e0344e88681905916f5",
        "cffi-2.0.0-cp312-cp312-win_amd64.whl",
    ),
    (
        "https://files.pythonhosted.org/packages/a0/e3/59cd50310fc9b59512193629e1984c1f95e5c8ae6e5d8c69532ccc65a7fe/pycparser-2.23-py3-none-any.whl",
        "e5c6e8d3fbad53479cab09ac03729e0a9faf2bee3db8208a550daf5af81a5934",
        "pycparser-2.23-py3-none-any.whl",
    ),
]


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(url: str, dest: Path, expect: str) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and sha256(dest) == expect:
        return dest
    urllib.request.urlretrieve(url, dest)
    got = sha256(dest)
    if got != expect:
        dest.unlink(missing_ok=True)
        raise SystemExit(f"hash mismatch {dest.name} {got} != {expect}")
    return dest


def run(cmd: list[str]) -> None:
    subprocess.check_call(cmd)


def zig() -> str:
    env = os.environ.get("HERMES_ZIG", "").strip()
    if env:
        return env
    found = shutil.which("zig")
    if found:
        return found
    raise SystemExit("zig not on PATH (need 0.14.1)")


def build_payload() -> Path:
    if STAGE.exists():
        shutil.rmtree(STAGE)
    runtime = STAGE / "runtime"
    runtime.mkdir(parents=True)
    embed = fetch(EMBED_URL, CACHE / "python-3.12.10-embed-amd64.zip", EMBED_SHA)
    run(["unzip", "-q", str(embed), "-d", str(runtime)])
    pth = next(runtime.glob("python*._pth"))
    text = pth.read_text()
    lines = []
    for line in text.splitlines():
        if line.strip().startswith("#") and "import site" in line:
            lines.append("import site")
        else:
            lines.append(line)
    if "Lib\\site-packages" not in text:
        out = []
        for line in lines:
            if line.strip() == "import site":
                out.append("Lib\\site-packages")
            out.append(line)
        lines = out
    pth.write_text("\n".join(lines) + "\n")
    site = runtime / "Lib" / "site-packages"
    site.mkdir(parents=True, exist_ok=True)
    for url, digest, name in WHEELS:
        whl = fetch(url, CACHE / name, digest)
        run(["unzip", "-qo", str(whl), "-d", str(site)])
    shutil.copytree(ROOT / "src" / "hermes_core", site / "hermes_core", dirs_exist_ok=True)
    shutil.copy2(ROOT / "windows-setup" / "setup.pyw", STAGE / "setup.pyw")
    shutil.copy2(INST / "src" / "background.pyw", STAGE / "background.pyw")
    return STAGE


def compile_pe(src: Path, out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    run(
        [
            zig(),
            "cc",
            "-target",
            "x86_64-windows-gnu",
            "-O2",
            "-s",
            "-Wl,--subsystem,windows",
            "-luser32",
            "-lshell32",
            "-ladvapi32",
            "-lole32",
            "-luuid",
            str(src),
            "-o",
            str(out),
        ]
    )


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    payload = build_payload()
    compile_pe(INST / "src" / "launcher.c", payload / "HermesCore.exe")
    stub = INST / "build" / "HermesCoreSetup-stub.exe"
    compile_pe(INST / "src" / "installer.c", stub)
    zip_path = INST / "build" / "payload.zip"
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in payload.rglob("*"):
            if p.is_file():
                zf.write(p, p.relative_to(payload).as_posix())
    final = OUT_DIR / "HermesCoreSetup-0.1.2.exe"
    data = stub.read_bytes() + zip_path.read_bytes()
    data += struct.pack("<Q", zip_path.stat().st_size) + MAGIC
    final.write_bytes(data)
    rel = {
        "filename": final.name,
        "sha256": sha256(final),
        "size": final.stat().st_size,
        "arch": "x86_64",
        "core_version": "0.1.2",
        "installer_version": "0.1.2-win1",
        "authenticode": "UNSIGNED_ENGINEERING",
        "built_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    (OUT_DIR / "RELEASE.json").write_text(json.dumps(rel, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(rel, indent=2))


if __name__ == "__main__":
    main()
