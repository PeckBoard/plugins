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
TAG_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")

REQUIRED = ["id", "name", "description", "author", "version", "hooks", "url", "sha256"]
ALLOWED = set(REQUIRED) | {"homepage", "min_peckboard", "tags", "category"}

# MCP server templates: Settings → MCP Servers entries with one-click add.
# Nothing is downloaded, so no version/sha256 — the entry mirrors the editor.
MCP_REQUIRED = ["id", "name", "description", "transport"]
MCP_ALLOWED = set(MCP_REQUIRED) | {
    "author",
    "homepage",
    "command",
    "args",
    "env",
    "headers",
    "url",
    "setup_note",
    "install",
    "oauth",
    "tags",
    "category",
    "min_peckboard",
}

# Optional OAuth sign-in template on http/sse MCP entries. `{}` alone means
# "OAuth-capable — discover everything from the server's .well-known
# metadata"; fields override individual pieces (see the McpOauthConfig
# struct in peckboard).
MCP_OAUTH_ALLOWED = {
    "authorize_url",
    "token_url",
    "registration_url",
    "client_id",
    "client_secret",
    "scopes",
    "scope_param",
    "token_field",
}

DOWNLOAD_CAP = 64 * 1024 * 1024  # 64 MiB — matches Peckboard's install cap.


def fail(errors):
    print(f"registry.json is INVALID ({len(errors)} error(s)):", file=sys.stderr)
    for e in errors:
        print(f"  - {e}", file=sys.stderr)
    sys.exit(1)


def check_tags_category(where, obj, errors):
    tags = obj.get("tags")
    if "tags" in obj:
        if not isinstance(tags, list) or not all(
            isinstance(t, str) and TAG_RE.match(t) for t in tags
        ):
            errors.append(f"{where}.tags must be an array of kebab-case strings")
        elif len(tags) != len(set(tags)):
            errors.append(f"{where}.tags has duplicates")
    cat = obj.get("category")
    if "category" in obj and (not isinstance(cat, str) or not TAG_RE.match(cat)):
        errors.append(f"{where}.category must be a kebab-case string")


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

        min_pb = p.get("min_peckboard")
        if "min_peckboard" in p and (not isinstance(min_pb, str) or not VERSION_RE.match(min_pb)):
            errors.append(f"{where}.min_peckboard `{min_pb}` must be semver-like")

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

        check_tags_category(where, p, errors)

    if "mcp_servers" in data:
        errors += validate_mcp_servers(data["mcp_servers"])

    return errors


def validate_mcp_servers(servers):
    errors = []
    if not isinstance(servers, list):
        return ["`mcp_servers` must be an array"]
    seen = set()
    for i, m in enumerate(servers):
        where = f"mcp_servers[{i}]"
        if not isinstance(m, dict):
            errors.append(f"{where} must be an object")
            continue
        for k in MCP_REQUIRED:
            if k not in m:
                errors.append(f"{where} missing required field `{k}`")
        for k in m:
            if k not in MCP_ALLOWED:
                errors.append(f"{where} has unknown field `{k}`")

        mid = m.get("id")
        if isinstance(mid, str):
            if not ID_RE.match(mid):
                errors.append(f"{where}.id `{mid}` must match {ID_RE.pattern}")
            if mid in seen:
                errors.append(f"{where}.id `{mid}` is duplicated")
            seen.add(mid)

        for field in ("name", "description"):
            v = m.get(field)
            if field in m and (not isinstance(v, str) or not v.strip()):
                errors.append(f"{where}.{field} must be a non-empty string")

        transport = m.get("transport")
        if "transport" in m and transport not in ("stdio", "http", "sse"):
            errors.append(f"{where}.transport `{transport}` must be stdio|http|sse")
        if transport == "stdio":
            cmd = m.get("command")
            if not isinstance(cmd, str) or not cmd.strip():
                errors.append(f"{where}.command is required for stdio transport")
        elif transport in ("http", "sse"):
            url = m.get("url")
            if not isinstance(url, str) or not url.startswith("https://"):
                errors.append(f"{where}.url must be an https:// URL for {transport} transport")

        args = m.get("args")
        if "args" in m and (not isinstance(args, list) or not all(isinstance(a, str) for a in args)):
            errors.append(f"{where}.args must be an array of strings")

        install = m.get("install")
        if "install" in m and (
            not isinstance(install, list)
            or not all(isinstance(s, str) and s.strip() for s in install)
        ):
            errors.append(f"{where}.install must be an array of non-empty strings")

        for list_field in ("env", "headers"):
            rows = m.get(list_field)
            if list_field in m:
                ok = isinstance(rows, list) and all(
                    isinstance(r, dict)
                    and set(r) <= {"key", "value"}
                    and isinstance(r.get("key"), str)
                    and r.get("key").strip()
                    and isinstance(r.get("value", ""), str)
                    for r in rows
                )
                if not ok:
                    errors.append(f"{where}.{list_field} must be an array of {{key, value}} string rows")

        homepage = m.get("homepage")
        oauth = m.get("oauth")
        if "oauth" in m:
            if not isinstance(oauth, dict):
                errors.append(f"{where}.oauth must be an object")
            else:
                if transport == "stdio":
                    errors.append(f"{where}.oauth only applies to http/sse transports")
                for k, v in oauth.items():
                    if k not in MCP_OAUTH_ALLOWED:
                        errors.append(f"{where}.oauth has unknown field `{k}`")
                    elif not isinstance(v, str) or not v.strip():
                        errors.append(f"{where}.oauth.{k} must be a non-empty string")

        if "homepage" in m and (not isinstance(homepage, str) or not homepage.startswith("https://")):
            errors.append(f"{where}.homepage must be an https:// URL")

        min_pb = m.get("min_peckboard")
        if "min_peckboard" in m and (not isinstance(min_pb, str) or not VERSION_RE.match(min_pb)):
            errors.append(f"{where}.min_peckboard `{min_pb}` must be semver-like")

        check_tags_category(where, m, errors)

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
    mcp_count = len(data.get("mcp_servers", []))
    print(f"registry.json structure OK ({len(data['plugins'])} plugin(s), {mcp_count} mcp server(s))")

    if do_checksums:
        print("verifying checksums...")
        errors = verify_checksums(data["plugins"])
        if errors:
            fail(errors)
        print("all checksums OK")


if __name__ == "__main__":
    main()
