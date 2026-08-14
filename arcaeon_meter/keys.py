"""Key management for arcaeon_meter.

Secrets are random (`secrets.token_urlsafe`), shown ONCE at creation, and
stored only as sha256 hashes — the keys file never contains a plaintext
secret, so leaking the file does not leak the keys. Revocation marks the
entry (kept for audit/export) rather than deleting it.

File shape (`keys.json`):

    {"version": 1,
     "keys": {"<sha256 hex>": {"plan": "free", "monthly_cap": 100,
                               "label": "alice", "created": "...",
                               "revoked": false}}}
"""
from __future__ import annotations

import json
import os
import secrets as _secrets
import tempfile
from pathlib import Path
from typing import Optional

from arcaeon_meter import KEY_PREFIX, key_hash, _now_iso


def new_secret() -> str:
    """A fresh random API key. ~192 bits of entropy, `am_` prefixed so keys
    are recognizable in configs and distinguishable from key_ids."""
    return KEY_PREFIX + _secrets.token_urlsafe(24)


def load(path: "str | Path") -> dict:
    p = Path(path)
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except OSError:
        return {"version": 1, "keys": {}}
    if not isinstance(doc, dict) or not isinstance(doc.get("keys"), dict):
        raise ValueError(f"{p}: not an arcaeon_meter keys file")
    return doc


def save(path: "str | Path", doc: dict) -> None:
    """Atomic write (temp file + os.replace) so a crash mid-save never
    leaves a half-written keys file."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=p.name, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.replace(tmp, str(p))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def add_key(path: "str | Path", *, plan: str = "free",
            monthly_cap: "int | None" = 100,
            label: Optional[str] = None) -> "tuple[str, str]":
    """Create a key; returns (secret, key_id). The secret exists only in
    this return value — store it now or mint another.

    `monthly_cap=None` means EXPLICIT unlimited (stored as null). To defer
    the cap to a plan default passed to `Meter(plans=...)`, use
    `monthly_cap="plan"` — the entry then carries no cap of its own.
    """
    doc = load(path)
    secret = new_secret()
    h = key_hash(secret)
    entry: dict = {"plan": plan, "created": _now_iso(), "revoked": False}
    if monthly_cap != "plan":
        entry["monthly_cap"] = monthly_cap
    if label is not None:
        entry["label"] = label
    doc["keys"][h] = entry
    save(path, doc)
    return secret, h[:12]


def _find(doc: dict, ident: str) -> str:
    """Resolve a secret or a key_id prefix to the stored full hash."""
    if ident.startswith(KEY_PREFIX):
        h = key_hash(ident)
        if h in doc["keys"]:
            return h
        raise KeyError(f"unknown key (id {h[:12]})")
    matches = [h for h in doc["keys"] if h.startswith(ident)]
    if not matches:
        raise KeyError(f"no key with id {ident!r}")
    if len(matches) > 1:
        raise KeyError(f"key id {ident!r} is ambiguous ({len(matches)} matches)")
    return matches[0]


def revoke_key(path: "str | Path", ident: str) -> str:
    """Revoke by secret or key_id; returns the key_id. Idempotent."""
    doc = load(path)
    h = _find(doc, ident)
    doc["keys"][h]["revoked"] = True
    doc["keys"][h]["revoked_at"] = _now_iso()
    save(path, doc)
    return h[:12]


def list_keys(path: "str | Path") -> "list[dict]":
    """All entries with their public key_ids — never secrets (none exist
    at rest to leak)."""
    doc = load(path)
    out = []
    for h, entry in sorted(doc["keys"].items()):
        row = {"key_id": h[:12]}
        row.update(entry)
        out.append(row)
    return out
