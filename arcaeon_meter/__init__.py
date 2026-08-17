# SPDX-License-Identifier: MIT
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
never at rest. Counts live in SQLite (WAL), keyed on the FULL key hash and
incremented inside an IMMEDIATE transaction, so concurrent processes don't
lose counts and no two customers can share a billing row. (`key_id`, the
12-hex prefix, is a display label only — 48 bits collide at scale; through
0.1.1 the counts were keyed on it, which merged colliding customers' usage.
See the migration note in `Meter._migrate_truncated_keyspace`.)

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

import contextlib
import functools
import hashlib
import os
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

__version__ = "0.1.3"
__all__ = ["Meter", "Allowance", "Denied", "MeterDenied", "Usage",
           "key_hash", "key_id_of", "KEY_PREFIX", "LEGACY_KEYSPACE_PREFIX"]

KEY_PREFIX = "am_"  # every issued secret starts with this

# Marker for usage rows migrated out of the pre-0.1.2 truncated keyspace that
# could not be re-attributed to exactly one key. See `Meter.legacy_usage()`.
LEGACY_KEYSPACE_PREFIX = "legacy_truncated_keyspace:"


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

    DISPLAY ONLY — not a billing identity. Safe to log, export, and show in
    dashboards; cannot be reversed to the secret and is not sufficient to
    authenticate. It is 48 bits, so two keys can share one (birthday odds hit
    ~50% around 16.7M keys). Counts, caps, and invoice rows are keyed on the
    FULL sha256 (`key_hash`) precisely so a display collision can never merge
    two customers' billing; the export carries both.
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
    - "no_cap_configured" key has no cap, its plan resolves to none, or the
                          configured cap is not a cap (NaN, Infinity, "100",
                          a list, a negative) — the meter fails CLOSED rather
                          than silently treating a misconfigured key as
                          unlimited
    - "malformed_key"     the presented key is not a usable string (wrong
                          type, or un-encodable text like a lone surrogate,
                          which is legal JSON and therefore arrives from
                          the wire)
    - "keys_unreadable"   the keys file exists but cannot be parsed. Not the
                          same as "no keys": the authorization record can't
                          be read, so nothing is authorized
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
    """Read-only usage snapshot for one key (no increment).

    `key_id` is the 12-hex display prefix; `key_hash` is the full sha256 the
    count is actually keyed on — the unambiguous billing identity.
    """
    key_id: str
    plan: str
    used: int
    cap: Optional[int]
    month: str
    label: Optional[str] = None
    revoked: bool = False
    key_hash: Optional[str] = None

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

    _CREATE_USAGE = (
        "CREATE TABLE IF NOT EXISTS usage ("
        " key_hash TEXT NOT NULL, month TEXT NOT NULL,"
        " used INTEGER NOT NULL DEFAULT 0,"
        " PRIMARY KEY (key_hash, month))")

    def _init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        con = self._connect()
        try:
            con.execute("PRAGMA journal_mode=WAL")
            cols = [r[1] for r in con.execute("PRAGMA table_info(usage)")]
            if cols and "key_hash" not in cols:
                self._migrate_truncated_keyspace(con)
            else:
                con.execute(self._CREATE_USAGE)
        finally:
            con.close()

    def _migrate_truncated_keyspace(self, con: sqlite3.Connection) -> None:
        """Move a pre-0.1.2 `usage` table off the 48-bit truncated key_id.

        Before 0.1.2 the counts were keyed on `sha256(secret)[:12]`. That is 48
        bits: two customers sharing those 12 hex shared one billing row, and
        `export()` invoiced both for the sum. Counting now keys on the full
        hash, which leaves the old rows to be re-attributed.

        What this can recover: a legacy row whose 12-hex prefix matches
        EXACTLY ONE key in the current keys file. The roster is the whole
        universe of keys that could have incremented it, so a single match is
        the right owner, and the count carries over intact.

        What it cannot: a prefix matching two or more roster keys — the merged
        row is the defect itself and truncation is not reversible, so there is
        no honest way to split it. Same for a prefix matching NO roster key
        (a hand-deleted entry; revoke keeps entries, so this is rare). Those
        rows are preserved under `legacy_truncated_keyspace:<prefix>` — never
        billed to anyone, never silently dropped, readable via
        `legacy_usage()`. The original table is kept as `usage_pre_0_1_2`.

        Caveat, stated rather than papered over: if entries were DELETED from
        keys.json (not revoked) after they had spent, a surviving key sharing
        the prefix inherits their counts. Deletion already destroys the
        evidence; the migration cannot invent it back.
        """
        try:
            roster = list(self._load_keys().keys())
        except (ValueError, OSError, UnicodeDecodeError) as e:
            # Migrating without the roster would zero every recoverable count
            # (i.e. hand every customer their budget back). Fail loud instead.
            raise RuntimeError(
                f"{self.db_path}: usage table uses the pre-0.1.2 truncated "
                f"keyspace and must be migrated, but the keys file "
                f"{self.keys_path} could not be read — fix the keys file, "
                f"then reopen the Meter") from e
        by_prefix: "dict[str, list[str]]" = {}
        for h in roster:
            by_prefix.setdefault(h[:12], []).append(h)
        archive = "usage_pre_0_1_2"
        n = 1
        while con.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                          "AND name=?", (archive,)).fetchone():
            n += 1
            archive = f"usage_pre_0_1_2_{n}"
        con.execute("BEGIN IMMEDIATE")
        try:
            rows = con.execute("SELECT key_id, month, used FROM usage").fetchall()
            con.execute(f"ALTER TABLE usage RENAME TO {archive}")
            con.execute(self._CREATE_USAGE)
            resolved = orphaned = 0
            for kid, month, used in rows:
                matches = by_prefix.get(kid, ())
                if len(matches) == 1:
                    target, resolved = matches[0], resolved + 1
                else:
                    target = LEGACY_KEYSPACE_PREFIX + str(kid)
                    orphaned += 1
                con.execute(
                    "INSERT INTO usage (key_hash, month, used) VALUES (?,?,?) "
                    "ON CONFLICT(key_hash, month) DO UPDATE SET used=used+?",
                    (target, month, used, used))
            con.execute("COMMIT")
        except BaseException:
            with contextlib.suppress(sqlite3.Error):
                con.execute("ROLLBACK")
            raise
        self._log("meter.migration", {
            "from": "key_id_12hex", "to": "key_hash_sha256",
            "rows": len(rows), "resolved": resolved, "unattributable": orphaned,
            "archive_table": archive, "at": _now_iso()})

    def _load_keys(self) -> "dict[str, dict]":
        """Keys, cached against the file's stat stamp.

        A missing file is an empty roster (every key then denies as
        unknown_key — fail closed). An UNREADABLE file is different: it is
        not "no keys," it is "the authorization record cannot be read," and
        that raises so `check()` can turn it into a typed keys_unreadable
        denial instead of blowing up three frames down in `json`.
        """
        try:
            st = self.keys_path.stat()
        except OSError:
            return {}
        # size + inode alongside mtime: a coarse-granularity filesystem
        # (FAT/ext3/many network mounts) or a timestamp-preserving copy
        # (rsync -t, restore-from-backup) can change content without moving
        # mtime, which would leave a revoked key spending until restart.
        stamp = (getattr(st, "st_mtime_ns", st.st_mtime), st.st_size,
                 getattr(st, "st_ino", 0), getattr(st, "st_ctime_ns", 0))
        if self._keys_mtime != stamp:
            from arcaeon_meter.keys import load
            self._keys_cache = load(self.keys_path).get("keys", {})
            self._keys_mtime = stamp
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
        # `cost` is a public kwarg and the SQL is `used = used + ?`. A negative
        # cost is an unbounded refund that persists in SQLite across processes;
        # cost=0 is unlimited free calls at the cap. Neither is a metering
        # event, so neither is accepted — loudly, before anything is read.
        if isinstance(cost, bool) or not isinstance(cost, int) or cost < 1:
            raise ValueError(f"cost must be a positive int, got {cost!r}")
        if not key:
            return self._deny(Denied(reason="missing_key", month=month))
        # A key arrives from the wire. It may be any JSON value, including a
        # lone surrogate (legal JSON, un-encodable UTF-8). Every one of those
        # used to escape `except MeterDenied` as a raw TypeError/
        # UnicodeEncodeError and 500 instead of 401.
        if not isinstance(key, str):
            return self._deny(Denied(reason="malformed_key", month=month))
        try:
            kh, kid = key_hash(key), key_id_of(key)
        except (UnicodeEncodeError, ValueError, TypeError):
            return self._deny(Denied(reason="malformed_key", month=month))
        try:
            entry = self._load_keys().get(kh)
        except (ValueError, OSError, UnicodeDecodeError):
            # corrupt / truncated / not-a-keys-file: we cannot read the
            # authorization record, so we do not authorize.
            return self._deny(Denied(reason="keys_unreadable", month=month,
                                     key_id=kid))
        if not isinstance(entry, dict):
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
            # Counts key on the FULL hash, never the 12-hex display id: that
            # prefix is 48 bits, and two customers colliding on it used to
            # share one row — one paying for the other's traffic, both capped
            # by the sum. `kid` stays a label on the way out.
            row = con.execute(
                "SELECT used FROM usage WHERE key_hash=? AND month=?",
                (kh, month)).fetchone()
            used = row[0] if row else 0
            if cap is not None and used + cost > cap:
                con.execute("ROLLBACK")
                return self._deny(Denied(reason="over_cap", month=month,
                                         key_id=kid, used=used, cap=cap))
            if record:
                con.execute(
                    "INSERT INTO usage (key_hash, month, used) VALUES (?,?,?) "
                    "ON CONFLICT(key_hash, month) DO UPDATE SET used=used+?",
                    (kh, month, cost, cost))
                used += cost
                # Chain the grant BEFORE committing the count. The other order
                # bills for a call whose ledger row was never written and whose
                # caller got an exception instead of the work — and verify()
                # reports ok across that gap, because the gap is a missing row,
                # not an altered one. If the log can't be written, the count
                # rolls back and nobody is charged.
                self._log("meter.grant", {"key_id": kid, "plan": plan,
                                          "month": month, "used": used,
                                          "cap": cap, "cost": cost})
            try:
                con.execute("COMMIT")
            except BaseException:
                # The other direction of the same seam: the ledger row is
                # already chained, and COMMIT just failed (disk full, I/O
                # error), so SQLite has no such grant. The row cannot be
                # removed without breaking the chain — so chain its INVERSE.
                # The receipt invariant is therefore grants MINUS voids ==
                # the billed count, and it survives a half-failed write.
                if record:
                    with contextlib.suppress(Exception):
                        self._log("meter.void", {
                            "key_id": kid, "plan": plan, "month": month,
                            "used": used, "cap": cap, "cost": cost,
                            "reason": "commit_failed"})
                raise
        finally:
            con.close()
        return Allowance(key_id=kid, plan=plan, used=used, cap=cap, month=month)

    @staticmethod
    def _valid_cap(cap: Any) -> bool:
        """A cap is None (explicit unlimited) or a non-negative int. NOT a
        float: `used + cost > nan` and `> inf` are both False, so a NaN or
        Infinity cap read straight out of a keys file was a silent unlimited
        grant — and `json.loads` accepts the bare `NaN`/`Infinity` literals,
        so it round-trips through this package's own writer. NOT a str or a
        list either: those raised a TypeError from the comparison."""
        if cap is None:
            return True
        return isinstance(cap, int) and not isinstance(cap, bool) and cap >= 0

    def _resolve_cap(self, entry: dict) -> "int | None | object":
        """Entry's own monthly_cap wins; else the plan default; else _NO_CAP
        (fail closed — an unconfigured key is not silently unlimited).
        Unlimited must be EXPLICIT: `"monthly_cap": null` in the entry, or a
        None plan default. A cap that isn't a cap is _NO_CAP, never a pass."""
        if "monthly_cap" in entry:
            cap = entry["monthly_cap"]
            return cap if self._valid_cap(cap) else _NO_CAP
        plan = entry.get("plan")
        if isinstance(plan, str) and plan in self.plans:
            cap = self.plans[plan]
            return cap if self._valid_cap(cap) else _NO_CAP
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
        if not isinstance(key_or_id, str):
            raise KeyError(f"key must be a string, got {type(key_or_id).__name__}")
        if key_or_id.startswith(KEY_PREFIX):
            h = key_hash(key_or_id)
            entry = keys.get(h)
            kid = h[:12]
        else:
            if len(key_or_id) < 6:
                # "" is a prefix of every hash — it would report a key at random.
                raise KeyError(f"key_id {key_or_id!r} is too short to be "
                               f"unambiguous (need at least 6 hex chars)")
            kid = key_or_id
            matches = [(h, e) for h, e in keys.items() if h.startswith(kid)]
            if len(matches) > 1:
                raise KeyError(f"key_id prefix {kid!r} is ambiguous")
            entry = matches[0][1] if matches else None
            h = matches[0][0] if matches else None
            kid = matches[0][0][:12] if matches else kid
        if entry is None or h is None:
            raise KeyError(f"unknown key: {key_or_id[:12]}...")
        m = month or _utc_month()
        con = self._connect()
        try:
            row = con.execute("SELECT used FROM usage WHERE key_hash=? AND month=?",
                              (h, m)).fetchone()
        finally:
            con.close()
        cap = self._resolve_cap(entry)
        return Usage(key_id=kid, key_hash=h, plan=entry.get("plan", "default"),
                     used=row[0] if row else 0,
                     cap=None if cap is _NO_CAP else cap, month=m,
                     label=entry.get("label"), revoked=bool(entry.get("revoked")))

    def legacy_usage(self, *, month: "str | None" = None) -> "list[dict]":
        """Pre-0.1.2 rows the migration could not attribute to exactly one key.

        Empty for any database created at 0.1.2 or later, which is the normal
        case. A non-empty list means counts exist that the old 48-bit keyspace
        merged or orphaned: they are preserved, deliberately NOT in `export()`
        (nobody can be honestly invoiced for them), and this is the reader.
        `month=None` returns every month.
        """
        con = self._connect()
        try:
            if month is None:
                rows = con.execute(
                    "SELECT key_hash, month, used FROM usage "
                    "WHERE key_hash LIKE ? ORDER BY month, key_hash",
                    (LEGACY_KEYSPACE_PREFIX + "%",)).fetchall()
            else:
                rows = con.execute(
                    "SELECT key_hash, month, used FROM usage "
                    "WHERE key_hash LIKE ? AND month=? ORDER BY key_hash",
                    (LEGACY_KEYSPACE_PREFIX + "%", month)).fetchall()
        finally:
            con.close()
        return [{"legacy_key_id": k[len(LEGACY_KEYSPACE_PREFIX):],
                 "month": mo, "used": u} for k, mo, u in rows]

    def export(self, *, month: "str | None" = None,
               fmt: str = "json") -> str:
        """Whole-roster usage for a month, for your billing flow.

        Every key in the keys file appears (zero-usage keys included — an
        invoice run wants the full roster). `fmt` is "json" (a list of row
        objects) or "csv" (header + rows). Columns: key_id, key_hash, label,
        plan, used, monthly_cap, revoked, month.

        `key_hash` (full sha256) is the identity to map to a customer:
        `key_id` is a 12-hex display prefix and two keys CAN share one, which
        would collapse two invoice lines into one lookup. It is the same
        one-way hash already stored in keys.json — not a secret, and not
        reversible to one. Plaintext secrets appear nowhere, as ever.

        Rows the pre-0.1.2 migration could not attribute to one key are
        deliberately absent (see `legacy_usage()`): nobody can be honestly
        invoiced for a count that belongs to an unknown owner.
        """
        m = month or _utc_month()
        keys = self._load_keys()
        con = self._connect()
        try:
            counts = dict(con.execute(
                "SELECT key_hash, used FROM usage WHERE month=?", (m,)).fetchall())
        finally:
            con.close()
        rows = []
        for h, entry in sorted(keys.items()):
            cap = self._resolve_cap(entry)
            rows.append({
                "key_id": h[:12],
                "key_hash": h,
                "label": entry.get("label"),
                "plan": entry.get("plan", "default"),
                "used": counts.get(h, 0),
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
            cols = ["key_id", "key_hash", "label", "plan", "used",
                    "monthly_cap", "revoked", "month"]
            w = _csv.DictWriter(buf, fieldnames=cols, lineterminator="\n")
            w.writeheader()
            w.writerows(rows)
            return buf.getvalue()
        raise ValueError(f"fmt must be 'json' or 'csv', not {fmt!r}")

    # -- http helper --------------------------------------------------------
    def asgi_middleware(self, *, skip_methods: "tuple[str, ...]" = ("OPTIONS",)):
        """A pure-ASGI middleware class checking `Authorization: Bearer <key>`.

        Works with FastAPI/Starlette (`app.add_middleware(meter.asgi_middleware())`)
        or any raw ASGI app (`app = meter.asgi_middleware()(app)`). Needs no
        framework installed — it speaks the ASGI protocol directly. Denials
        answer 401 (missing/unknown/revoked key) or 429 (over cap) with a
        JSON body naming the reason; grants stash the `Allowance` at
        `scope["arcaeon_meter"]` for your handlers.

        `skip_methods` are passed through unmetered and unauthenticated
        (`scope["arcaeon_meter"] = None`). The default exists for CORS: a
        browser preflight is a protocol question, not a call — and it carries
        no Authorization header, so metering it both billed a non-call and
        answered 401, which breaks CORS outright. Add `"HEAD"` if you do not
        consider a HEAD a billable call. Everything else IS billed at
        dispatch, including requests your handler answers 5xx — see the
        README's billing-policy note for why that ordering is deliberate.
        """
        from arcaeon_meter.asgi import build_middleware
        return build_middleware(self, skip_methods=skip_methods)


class _NoCapSentinel:
    """Distinct from None (None = explicit unlimited)."""
    def __repr__(self) -> str:  # pragma: no cover
        return "<no cap configured>"


_NO_CAP: Any = _NoCapSentinel()
