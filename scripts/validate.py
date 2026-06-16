#!/usr/bin/env python3
"""Validate registry.json for the Peckboard plugin registry.

Structural checks run with the standard library only (no pip deps), so the
CI gate stays dependency-free. Pass --verify-checksums to additionally
download each plugin .wasm and confirm its SHA-256 matches the index (this
one needs network access).

Usage:
    python scripts/validate.py [--verify-checksums] [path/to/registry.json]
"""

import hashlib
import json
import re
import sys
import urllib.request

ID_RE = re.compile(r"^[a-z0-9_-]+$")
HOOK_RE = re.compile(r"^[a-z][a-z0-9_.]*$")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+([.-].+)?$")

REQUIRED = ["id", "name", "description", "author", "version", "hooks", "url", "sha256"]
ALLOWED = set(REQUIRED) | {"homepage"}

DOWNLOAD_CAP = 64 * 1024 * 1024  # 64 MiB — matches Peckboard's install cap.


def fail(errors):
    print(f"registry.json is INVALID ({len(errors)} error(s)):", file=sys.stderr)
    for e in errors:
        print(f"  - {e}", file=sys.stderr)
    sys.exit(1)


def validate_structure(data):
    errors = []
    if not isinstance(data, dict):
        return ["top level must be an object"]
    if data.get("schema_version") != 1:
        errors.append("schema_version must be the integer 1")
    plugins = data.get("plugins")
    if not isinstance(plugins, list):
        return errors + ["`plugins` must be an array"]

    seen_ids = set()
    for i, p in enumerate(plugins):
        where = f"plugins[{i}]"
        if not isinstance(p, dict):
            errors.append(f"{where} must be an object")
            continue
        for k in REQUIRED:
            if k not in p:
                errors.append(f"{where} missing required field `{k}`")
        for k in p:
            if k not in ALLOWED:
                errors.append(f"{where} has unknown field `{k}`")

        pid = p.get("id")
        if isinstance(pid, str):
            if not ID_RE.match(pid):
                errors.append(f"{where}.id `{pid}` must match {ID_RE.pattern}")
            if pid in seen_ids:
                errors.append(f"{where}.id `{pid}` is duplicated")
            seen_ids.add(pid)

        for field in ("name", "description", "author"):
            v = p.get(field)
            if field in p and (not isinstance(v, str) or not v.strip()):
                errors.append(f"{where}.{field} must be a non-empty string")

        ver = p.get("version")
        if "version" in p and (not isinstance(ver, str) or not VERSION_RE.match(ver)):
            errors.append(f"{where}.version `{ver}` must be semver-like")

        hooks = p.get("hooks")
        if "hooks" in p:
            if not isinstance(hooks, list) or not hooks:
                errors.append(f"{where}.hooks must be a non-empty array")
            else:
                if len(hooks) != len(set(hooks)):
                    errors.append(f"{where}.hooks has duplicates")
                for h in hooks:
                    if not isinstance(h, str) or not HOOK_RE.match(h):
                        errors.append(f"{where}.hooks entry `{h}` is not a valid hook id")

        url = p.get("url")
        if "url" in p and (not isinstance(url, str) or not url.startswith("https://")):
            errors.append(f"{where}.url must be an https:// URL")

        homepage = p.get("homepage")
        if "homepage" in p and (not isinstance(homepage, str) or not homepage.startswith("https://")):
            errors.append(f"{where}.homepage must be an https:// URL")

        sha = p.get("sha256")
        if "sha256" in p and (not isinstance(sha, str) or not SHA256_RE.match(sha)):
            errors.append(f"{where}.sha256 must be 64 lowercase hex chars")

    return errors


def verify_checksums(plugins):
    errors = []
    for p in plugins:
        pid, url, expected = p.get("id"), p.get("url"), p.get("sha256")
        print(f"  downloading {pid} <- {url}")
        try:
            with urllib.request.urlopen(url, timeout=60) as resp:
                data = resp.read(DOWNLOAD_CAP + 1)
        except Exception as exc:  # noqa: BLE001 - surface any fetch failure
            errors.append(f"{pid}: download failed: {exc}")
            continue
        if len(data) > DOWNLOAD_CAP:
            errors.append(f"{pid}: download exceeds {DOWNLOAD_CAP} bytes")
            continue
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            errors.append(f"{pid}: sha256 mismatch (index {expected}, actual {actual})")
        elif not data.startswith(b"\x00asm"):
            errors.append(f"{pid}: downloaded bytes are not a WASM module")
    return errors


def main():
    args = sys.argv[1:]
    do_checksums = "--verify-checksums" in args
    args = [a for a in args if a != "--verify-checksums"]
    path = args[0] if args else "registry.json"

    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)

    errors = validate_structure(data)
    if errors:
        fail(errors)
    print(f"registry.json structure OK ({len(data['plugins'])} plugin(s))")

    if do_checksums:
        print("verifying checksums...")
        errors = verify_checksums(data["plugins"])
        if errors:
            fail(errors)
        print("all checksums OK")


if __name__ == "__main__":
    main()
