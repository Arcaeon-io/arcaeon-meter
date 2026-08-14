"""arcaeon_meter — keyed usage metering for agent tools, in 3 lines.

You built a tool agents want to call. Now you need keys, per-key monthly
caps, and a usage record you can bill from — without standing up billing
infrastructure. That's this:

    from arcaeon_meter import Meter
    meter = Meter("keys.json")

    @meter.metered
    def my_tool(query, _meter_key=None): ...

Every call checks the key, counts the use, and enforces the cap. Over-cap
or bad key raises `MeterDenied` — a typed, structured denial, never a
silent pass. `meter.usage(key)` and `meter.export()` hand the counts to
your billing flow (CSV/JSON, Stripe-invoice-ready).

Storage: keys live hashed (sha256) in a JSON file — plaintext secrets are
never at rest. Counts live in SQLite (WAL), incremented inside an IMMEDIATE
transaction, so concurrent processes don't lose counts.

WHAT IT PROVES, AND WHAT IT DOESN'T. An in-process wrapper meters what the
meter SAW: calls that go through the decorated path. Code that calls the
inner function directly bypasses it — this is the voluntary-path (gateway
completeness) problem, and no library-level wrapper escapes it; put the
meter at your real network boundary (see `asgi_middleware()`) to narrow it.
Caps are enforcement; payment is not included — export feeds YOUR billing.

Tamper-evident option: `Meter(..., ledger="usage.log.jsonl")` hash-chains
every grant and denial via arcaeon-ledger, so the metering record itself is
auditable. Soft dependency; only required if you pass `ledger=`.

Zero required dependencies (stdlib only). MIT.
"""
from __future__ import annotations

import functools
import hashlib
import os
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

__version__ = "0.1.0"
__all__ = ["Meter", "Allowance", "Denied", "MeterDenied", "Usage",
           "key_hash", "key_id_of", "KEY_PREFIX"]

KEY_PREFIX = "am_"  # every issued secret starts with this


def _utc_month() -> str:
    """Current UTC billing month, 'YYYY-MM'. Module-level so tests can patch."""
    return datetime.now(timezone.utc).strftime("%Y-%m")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def key_hash(secret: str) -> str:
    """sha256 hex of a presented secret — the only form stored at rest."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def key_id_of(secret: str) -> str:
    """Short public identifier for a key: first 12 hex of its hash.

    Safe to log, export, and show in dashboards; cannot be reversed to the
    secret and is not sufficient to authenticate.
    """
    return key_hash(secret)[:12]


@dataclass
class Allowance:
    """A granted call: who, how much used, how much remains."""
    key_id: str
    plan: str
    used: int            # count AFTER this grant
    cap: Optional[int]   # None = unlimited (explicitly configured)
    month: str
    ok: bool = field(default=True)

    @property
    def remaining(self) -> Optional[int]:
        return None if self.cap is None else max(0, self.cap - self.used)

    def __bool__(self) -> bool:
        return True


@dataclass
class Denied:
    """A structured denial. `reason` is machine-readable:

    - "missing_key"       no key presented
    - "unknown_key"       key not in the keys file
    - "revoked"           key exists but was revoked
    - "over_cap"          monthly cap reached (used/cap filled in)
    - "no_cap_configured" key has no cap and its plan resolves to none —
                          the meter fails CLOSED rather than silently
                          treating a misconfigured key as unlimited
    """
    reason: str
    month: str
    key_id: Optional[str] = None
    used: Optional[int] = None
    cap: Optional[int] = None
    ok: bool = field(default=False)

    def __bool__(self) -> bool:
        return False


@dataclass
class Usage:
    """Read-only usage snapshot for one key (no increment)."""
    key_id: str
    plan: str
    used: int
    cap: Optional[int]
    month: str
    label: Optional[str] = None
    revoked: bool = False

    @property
    def remaining(self) -> Optional[int]:
        return None if self.cap is None else max(0, self.cap - self.used)


class MeterDenied(Exception):
    """Raised by `@meter.metered` when a call is denied. Carries `.denial`
    (a `Denied` dataclass) so callers can branch on `.denial.reason`."""

    def __init__(self, denial: Denied):
        self.denial = denial
        super().__init__(
            f"meter denied ({denial.reason}): key_id={denial.key_id} "
            f"used={denial.used} cap={denial.cap} month={denial.month}")


class Meter:
    """Keyed metering over a hashed keys file + a SQLite usage store.

    - `keys`: path to the keys JSON (managed by `python -m arcaeon_meter
      keys add|revoke|list`). Stored entries are keyed by sha256 of the
      secret — plaintext keys are never at rest.
    - `db`: SQLite path for usage counts. Default: `<keys stem>_usage.sqlite3`
      next to the keys file.
    - `plans`: optional {plan_name: monthly_cap} defaults; a key entry's own
      `monthly_cap` wins over its plan's default.
    - `ledger`: optional path to a hash-chained JSONL (requires the
      `arcaeon-ledger` package). Every grant AND denial appends a chained
      row — metering whose own record is tamper-evident.

    The keys file is re-read when its mtime changes, so a CLI revocation
    takes effect in a running server without a restart.
    """

    def __init__(self, keys: "str | Path", *, db: "str | Path | None" = None,
                 plans: "dict[str, int | None] | None" = None,
                 ledger: "str | Path | None" = None):
        self.keys_path = Path(keys)
        self.db_path = (Path(db) if db is not None else
                        self.keys_path.with_name(self.keys_path.stem + "_usage.sqlite3"))
        self.plans: "dict[str, int | None]" = dict(plans or {})
        self._keys_cache: "dict[str, dict]" = {}
        self._keys_mtime: "float | None" = None
        self._ledger = None
        if ledger is not None:
            try:
                from arcaeon_ledger import Ledger as _Ledger
            except ImportError as e:  # soft dep, loud failure — never silent
                raise ImportError(
                    "Meter(ledger=...) requires the arcaeon-ledger package: "
                    "pip install 'arcaeon-meter[ledger]'") from e
            self._ledger = _Ledger(ledger)
        self._init_db()

    # -- storage ------------------------------------------------------------
    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(str(self.db_path), timeout=15,
                              isolation_level=None)  # explicit transactions
        con.execute("PRAGMA busy_timeout=15000")
        return con

    def _init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        con = self._connect()
        try:
            con.execute("PRAGMA journal_mode=WAL")
            con.execute(
                "CREATE TABLE IF NOT EXISTS usage ("
                " key_id TEXT NOT NULL, month TEXT NOT NULL,"
                " used INTEGER NOT NULL DEFAULT 0,"
                " PRIMARY KEY (key_id, month))")
        finally:
            con.close()

    def _load_keys(self) -> "dict[str, dict]":
        try:
            mtime = self.keys_path.stat().st_mtime
        except OSError:
            return {}
        if self._keys_mtime != mtime:
            from arcaeon_meter.keys import load
            self._keys_cache = load(self.keys_path).get("keys", {})
            self._keys_mtime = mtime
        return self._keys_cache

    # -- the verb -----------------------------------------------------------
    def check(self, key: "str | None", *, cost: int = 1,
              record: bool = True) -> "Allowance | Denied":
        """Check a key and (by default) count the use. Returns `Allowance`
        (truthy) or `Denied` (falsy) — branch with `if result:` or on
        `result.reason`. Never raises for a mere denial; the decorator does.

        `record=False` peeks (validates key + reports current usage) without
        incrementing. The increment runs inside a SQLite IMMEDIATE
        transaction: check-then-add is atomic across processes, so two
        workers can't both take the last slot under the cap.
        """
        month = _utc_month()
        if not key:
            return self._deny(Denied(reason="missing_key", month=month))
        entry = self._load_keys().get(key_hash(key))
        kid = key_id_of(key)
        if entry is None:
            return self._deny(Denied(reason="unknown_key", month=month, key_id=kid))
        if entry.get("revoked"):
            return self._deny(Denied(reason="revoked", month=month, key_id=kid))
        plan = entry.get("plan", "default")
        cap = self._resolve_cap(entry)
        if cap is _NO_CAP:
            return self._deny(Denied(reason="no_cap_configured", month=month,
                                     key_id=kid))
        con = self._connect()
        try:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute(
                "SELECT used FROM usage WHERE key_id=? AND month=?",
                (kid, month)).fetchone()
            used = row[0] if row else 0
            if cap is not None and used + cost > cap:
                con.execute("ROLLBACK")
                return self._deny(Denied(reason="over_cap", month=month,
                                         key_id=kid, used=used, cap=cap))
            if record:
                con.execute(
                    "INSERT INTO usage (key_id, month, used) VALUES (?,?,?) "
                    "ON CONFLICT(key_id, month) DO UPDATE SET used=used+?",
                    (kid, month, cost, cost))
                used += cost
            con.execute("COMMIT")
        finally:
            con.close()
        allowance = Allowance(key_id=kid, plan=plan, used=used, cap=cap, month=month)
        if record:
            self._log("meter.grant", {"key_id": kid, "plan": plan, "month": month,
                                      "used": used, "cap": cap, "cost": cost})
        return allowance

    def _resolve_cap(self, entry: dict) -> "int | None | object":
        """Entry's own monthly_cap wins; else the plan default; else _NO_CAP
        (fail closed — an unconfigured key is not silently unlimited).
        Unlimited must be EXPLICIT: `"monthly_cap": null` in the entry, or a
        None plan default."""
        if "monthly_cap" in entry:
            return entry["monthly_cap"]  # may be None = explicit unlimited
        plan = entry.get("plan")
        if plan in self.plans:
            return self.plans[plan]
        return _NO_CAP

    def _deny(self, d: Denied) -> Denied:
        self._log("meter.deny", {"reason": d.reason, "key_id": d.key_id,
                                 "month": d.month, "used": d.used, "cap": d.cap})
        return d

    def _log(self, event: str, payload: "dict[str, Any]") -> None:
        if self._ledger is not None:
            row = {"event": event}
            row.update({k: v for k, v in payload.items() if v is not None})
            self._ledger.append(row)

    # -- decorator ----------------------------------------------------------
    def metered(self, fn: Callable) -> Callable:
        """Decorator: the wrapped function takes `_meter_key=` (the caller's
        secret). Denials raise `MeterDenied`; grants pass through with the
        kwargs untouched (your function may ignore `_meter_key`)."""
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            result = self.check(kwargs.get("_meter_key"))
            if not result:
                raise MeterDenied(result)
            return fn(*args, **kwargs)
        return wrapper

    # -- billing handoff ----------------------------------------------------
    def usage(self, key_or_id: str, *, month: "str | None" = None) -> Usage:
        """Usage snapshot (no increment) by secret or by 12-hex key_id.
        Raises KeyError for a key the keys file doesn't know."""
        keys = self._load_keys()
        if key_or_id.startswith(KEY_PREFIX):
            h = key_hash(key_or_id)
            entry = keys.get(h)
            kid = h[:12]
        else:
            kid = key_or_id
            matches = [(h, e) for h, e in keys.items() if h.startswith(kid)]
            if len(matches) > 1:
                raise KeyError(f"key_id prefix {kid!r} is ambiguous")
            entry = matches[0][1] if matches else None
            kid = matches[0][0][:12] if matches else kid
        if entry is None:
            raise KeyError(f"unknown key: {key_or_id[:12]}...")
        m = month or _utc_month()
        con = self._connect()
        try:
            row = con.execute("SELECT used FROM usage WHERE key_id=? AND month=?",
                              (kid, m)).fetchone()
        finally:
            con.close()
        cap = self._resolve_cap(entry)
        return Usage(key_id=kid, plan=entry.get("plan", "default"),
                     used=row[0] if row else 0,
                     cap=None if cap is _NO_CAP else cap, month=m,
                     label=entry.get("label"), revoked=bool(entry.get("revoked")))

    def export(self, *, month: "str | None" = None,
               fmt: str = "json") -> str:
        """Whole-roster usage for a month, for your billing flow.

        Every key in the keys file appears (zero-usage keys included — an
        invoice run wants the full roster). `fmt` is "json" (a list of row
        objects) or "csv" (header + rows). Columns: key_id, label, plan,
        used, monthly_cap, revoked, month. No secrets, no hashes beyond the
        12-hex key_id.
        """
        m = month or _utc_month()
        keys = self._load_keys()
        con = self._connect()
        try:
            counts = dict(con.execute(
                "SELECT key_id, used FROM usage WHERE month=?", (m,)).fetchall())
        finally:
            con.close()
        rows = []
        for h, entry in sorted(keys.items()):
            kid = h[:12]
            cap = self._resolve_cap(entry)
            rows.append({
                "key_id": kid,
                "label": entry.get("label"),
                "plan": entry.get("plan", "default"),
                "used": counts.get(kid, 0),
                "monthly_cap": None if cap is _NO_CAP else cap,
                "revoked": bool(entry.get("revoked")),
                "month": m,
            })
        if fmt == "json":
            import json as _json
            return _json.dumps(rows, indent=2)
        if fmt == "csv":
            import csv as _csv
            import io as _io
            buf = _io.StringIO()
            cols = ["key_id", "label", "plan", "used", "monthly_cap",
                    "revoked", "month"]
            w = _csv.DictWriter(buf, fieldnames=cols, lineterminator="\n")
            w.writeheader()
            w.writerows(rows)
            return buf.getvalue()
        raise ValueError(f"fmt must be 'json' or 'csv', not {fmt!r}")

    # -- http helper --------------------------------------------------------
    def asgi_middleware(self):
        """A pure-ASGI middleware class checking `Authorization: Bearer <key>`.

        Works with FastAPI/Starlette (`app.add_middleware(meter.asgi_middleware())`)
        or any raw ASGI app (`app = meter.asgi_middleware()(app)`). Needs no
        framework installed — it speaks the ASGI protocol directly. Denials
        answer 401 (missing/unknown/revoked key) or 429 (over cap) with a
        JSON body naming the reason; grants stash the `Allowance` at
        `scope["arcaeon_meter"]` for your handlers.
        """
        from arcaeon_meter.asgi import build_middleware
        return build_middleware(self)


class _NoCapSentinel:
    """Distinct from None (None = explicit unlimited)."""
    def __repr__(self) -> str:  # pragma: no cover
        return "<no cap configured>"


_NO_CAP: Any = _NoCapSentinel()
