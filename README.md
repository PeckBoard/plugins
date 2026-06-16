# Peckboard Plugin Registry

The catalog of installable [Peckboard](https://github.com/PeckBoard/peckboard)
WASM plugins. It is a **single static file**, [`registry.json`](registry.json),
that Peckboard fetches to show you what's available and to install a plugin you
choose.

There is no service here — just an index. Each plugin's actual `.wasm` is built
and published from its **own** repository (as a GitHub release asset); this
registry only points at those assets and records the SHA-256 Peckboard verifies
the download against.

## How install works (the trust model)

1. Peckboard fetches `registry.json` and lists the plugins.
2. You pick one. Peckboard downloads its `url`, computes the SHA-256, and
   **rejects the file if it doesn't match `sha256`** in the index.
3. The verified `.wasm` is saved as `<id>.wasm` in your data dir and loaded
   **inert** — none of its hooks run yet.
4. Peckboard prompts you to approve the exact set of `hooks` the plugin
   declares. Nothing the plugin declared executes until you approve.

So a plugin can never act on your data just by being listed or installed: the
checksum guards integrity against the index, and the per-plugin hook-approval
gate guards capability. A malicious or compromised entry still can't run a hook
you didn't approve.

## `registry.json` format

Validated by [`schema/registry.schema.json`](schema/registry.schema.json)
(JSON Schema draft 2020-12).

```json
{
  "schema_version": 1,
  "plugins": [
    {
      "id": "api",
      "name": "Public API Plugin",
      "description": "Public, API-key-authenticated HTTP surface for Peckboard …",
      "author": "PeckBoard",
      "homepage": "https://github.com/PeckBoard/api-plugin",
      "version": "0.2.0",
      "hooks": ["http.request.before"],
      "url": "https://github.com/PeckBoard/api-plugin/releases/download/v0.2.0/api.wasm",
      "sha256": "4ecb2ee49c3d85c323556f191f6d7fa3a5a0ec8ea9371daa952f17d577c86df2"
    }
  ]
}
```

| Field         | Required | Notes                                                                                                |
| ------------- | -------- | ---------------------------------------------------------------------------------------------------- |
| `id`          | yes      | Stable id. **Must equal the `.wasm` file stem** Peckboard saves it under — config and approval are keyed by it. `^[a-z0-9_-]+$`. |
| `name`        | yes      | Display name.                                                                                        |
| `description` | yes      | One- or two-sentence summary.                                                                        |
| `author`      | yes      | Publisher.                                                                                            |
| `homepage`    | no       | Source/docs URL (`https://`).                                                                         |
| `version`     | yes      | Semantic version of the published `.wasm`.                                                            |
| `hooks`       | yes      | Every hook the plugin declares — what the operator approves. Non-empty, unique.                       |
| `url`         | yes      | `https://` download URL of the `.wasm`.                                                               |
| `sha256`      | yes      | Lowercase hex SHA-256 of the bytes at `url`.                                                          |

## Adding or updating a plugin

1. Build and publish your plugin `.wasm` as a release asset in your own repo
   (see [`api-plugin`](https://github.com/PeckBoard/api-plugin) for a template).
2. Compute its checksum:
   ```bash
   curl -sL -o plugin.wasm "<your release asset url>"
   sha256sum plugin.wasm
   ```
3. Add (or update) your entry in `registry.json`. Keep `id` stable across
   versions; bump `version`, `url`, `sha256`, and `hooks` together.
4. Validate locally, then open a PR:
   ```bash
   python scripts/validate.py                     # structure
   python scripts/validate.py --verify-checksums  # downloads + checks sha256
   ```

CI runs both checks on every PR.

## Validation

[`scripts/validate.py`](scripts/validate.py) is standard-library only. It
checks the structure (required fields, id/hook/sha256 patterns, unique ids,
`https://` URLs) and, with `--verify-checksums`, downloads each `.wasm` and
confirms the SHA-256 and that the bytes are a real WASM module.
