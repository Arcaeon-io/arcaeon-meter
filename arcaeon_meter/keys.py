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

import contextlib
import json
import os
import secrets as _secrets
import tempfile
import time
from pathlib import Path
from typing import Optional

from arcaeon_meter import KEY_PREFIX, key_hash, _now_iso


def new_secret() -> str:
    """A fresh random API key. ~192 bits of entropy, `am_` prefixed so keys
    are recognizable in configs and distinguishable from key_ids."""
    return KEY_PREFIX + _secrets.token_urlsafe(24)


def _reject_constant(name: str):
    """json.loads accepts the bare literals NaN / Infinity / -Infinity by
    default. A cap is a count, none of those are counts, and a NaN cap
    compares False against everything (i.e. unlimited). Refuse at parse."""
    raise ValueError(f"keys file contains the non-JSON literal {name!r}")


def load(path: "str | Path") -> dict:
    p = Path(path)
    try:
        doc = json.loads(p.read_text(encoding="utf-8"),
                         parse_constant=_reject_constant)
    except OSError:
        return {"version": 1, "keys": {}}
    if not isinstance(doc, dict) or not isinstance(doc.get("keys"), dict):
        raise ValueError(f"{p}: not an arcaeon_meter keys file")
    return doc


@contextlib.contextmanager
def _locked(path: "str | Path", timeout: float = 10.0):
    """Cross-process mutex over the WHOLE load-mutate-save cycle.

    `save()` being atomic was never the issue — each write landed whole, and
    the transaction around it still lost. `add_key`/`revoke_key` are
    read-modify-write on one document, so a concurrent add rewrote the file
    from a stale read and silently un-revoked a key the CLI had just reported
    as revoked. A revocation that reports success and doesn't take is worse
    than one that fails.
    """
    lock = Path(str(path) + ".lock")
    lock.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + timeout
    while True:
        try:
            fd = os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_RDWR)
            break
        except FileExistsError:
            # A stale lock from a killed process shouldn't wedge the file
            # forever; past the deadline, break it rather than deadlock.
            try:
                if time.time() - lock.stat().st_mtime > timeout * 2:
                    os.unlink(lock)
                    continue
            except OSError:
                continue
            if time.monotonic() > deadline:
                raise TimeoutError(f"could not lock {path} within {timeout}s")
            time.sleep(0.01)
    try:
        yield
    finally:
        os.close(fd)
        with contextlib.suppress(OSError):
            os.unlink(lock)


def save(path: "str | Path", doc: dict) -> None:
    """Atomic write (temp file + fsync + os.replace) so neither a crash nor a
    power loss mid-save leaves a half-written keys file.

    On Windows `os.replace` fails with PermissionError while any reader holds
    the target open, so the rename retries briefly — without it, revoking a
    key while the server was serving crashed the CLI outright (README says
    revocation takes effect in a running server; it has to survive one).
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=p.name, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2, ensure_ascii=False, allow_nan=False)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        for attempt in range(50):
            try:
                os.replace(tmp, str(p))
                break
            except PermissionError:
                if attempt == 49:
                    raise
                time.sleep(0.02)
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
    with _locked(path):
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
    if not isinstance(ident, str):
        raise KeyError(f"key id must be a string, got {type(ident).__name__}")
    if ident.startswith(KEY_PREFIX):
        h = key_hash(ident)
        if h in doc["keys"]:
            return h
        raise KeyError(f"unknown key (id {h[:12]})")
    if len(ident) < 6:
        # "" matches the first key in the file; "a" matches whatever happens
        # to start with a. An unset $KEY_ID in an ops script must not revoke
        # a key at random.
        raise KeyError(f"key id {ident!r} is too short to be unambiguous "
                       f"(need at least 6 hex chars)")
    matches = [h for h in doc["keys"] if h.startswith(ident)]
    if not matches:
        raise KeyError(f"no key with id {ident!r}")
    if len(matches) > 1:
        raise KeyError(f"key id {ident!r} is ambiguous ({len(matches)} matches)")
    return matches[0]


def revoke_key(path: "str | Path", ident: str) -> str:
    """Revoke by secret or key_id; returns the key_id. Idempotent."""
    with _locked(path):
        doc = load(path)
        h = _find(doc, ident)
        doc["keys"][h]["revoked"] = True
        doc["keys"][h]["revoked_at"] = _now_iso()
        save(path, doc)
    return h[:12]


def list_keys(path: "str | Path") -> "list[dict]":
    """All entries with their public key_ids — never secrets (none exist
    at rest to leak).

    `key_id` is the 12-hex display prefix; `key_hash` is the full sha256 that
    counts and invoice rows are keyed on (two keys can share a prefix, so the
    prefix is a label, not an identity).
    """
    doc = load(path)
    out = []
    for h, entry in sorted(doc["keys"].items()):
        row = {"key_id": h[:12], "key_hash": h}
        row.update(entry)
        out.append(row)
    return out
