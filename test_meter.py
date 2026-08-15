"""Tests for arcaeon_meter — the product claim is 'caps are enforced, never
a silent pass,' so the denial paths (revoked, over-cap, unconfigured) are
the load-bearing tests. Run: python test_meter.py
"""
from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path

import arcaeon_meter
from arcaeon_meter import Meter, MeterDenied, key_id_of
from arcaeon_meter.keys import add_key, list_keys, revoke_key


def _mk(d: Path, **meter_kw):
    kp = d / "keys.json"
    secret, kid = add_key(kp, plan="free", monthly_cap=3, label="alice")
    return Meter(kp, **meter_kw), kp, secret, kid


def test_three_line_promise_and_grant_path():
    with tempfile.TemporaryDirectory() as td:
        meter, kp, secret, kid = _mk(Path(td))

        @meter.metered
        def my_tool(query, _meter_key=None):
            return f"result for {query}"

        assert my_tool("weather", _meter_key=secret) == "result for weather"
        a = meter.check(secret)
        assert a and a.ok and a.used == 2 and a.cap == 3 and a.remaining == 1
        assert a.key_id == kid and a.plan == "free"
    print("PASS 3-line decorator grants + counts (used=2/3 after two calls)")


def test_over_cap_denied_typed_never_silent():
    with tempfile.TemporaryDirectory() as td:
        meter, kp, secret, kid = _mk(Path(td))

        @meter.metered
        def my_tool(q, _meter_key=None):
            return "ok"

        for _ in range(3):
            my_tool("q", _meter_key=secret)
        try:
            my_tool("q", _meter_key=secret)
            raise AssertionError("over-cap call passed silently!")
        except MeterDenied as e:
            assert e.denial.reason == "over_cap"
            assert e.denial.used == 3 and e.denial.cap == 3
        # denial did NOT increment
        assert meter.usage(secret).used == 3
        # structured (non-raising) form agrees
        d = meter.check(secret)
        assert not d and d.reason == "over_cap"
    print("PASS over-cap -> MeterDenied(reason='over_cap', used=3, cap=3); "
          "denial does not increment")


def test_revoked_key_denied():
    with tempfile.TemporaryDirectory() as td:
        meter, kp, secret, kid = _mk(Path(td))
        assert meter.check(secret).ok
        assert revoke_key(kp, kid) == kid  # revoke by public key_id
        d = meter.check(secret)            # running Meter picks up the mtime change
        assert not d and d.reason == "revoked"
    print("PASS revoked key denied (reason='revoked'), no restart needed")


def test_unknown_and_missing_key_denied():
    with tempfile.TemporaryDirectory() as td:
        meter, kp, secret, kid = _mk(Path(td))
        assert meter.check("am_not-a-real-key").reason == "unknown_key"
        assert meter.check(None).reason == "missing_key"

        @meter.metered
        def my_tool(q, _meter_key=None):
            return "ok"
        try:
            my_tool("q")  # no key at all
            raise AssertionError("keyless call passed!")
        except MeterDenied as e:
            assert e.denial.reason == "missing_key"
    print("PASS unknown/missing key denied (typed reasons)")


def test_unconfigured_cap_fails_closed():
    with tempfile.TemporaryDirectory() as td:
        kp = Path(td) / "keys.json"
        secret, kid = add_key(kp, plan="mystery", monthly_cap="plan")  # defer to plan
        meter = Meter(kp)  # ...but no plans given
        d = meter.check(secret)
        assert not d and d.reason == "no_cap_configured"
        # with the plan default supplied, same key works
        meter2 = Meter(kp, plans={"mystery": 5})
        assert meter2.check(secret).cap == 5
        # and explicit unlimited is honored, not confused with unconfigured
        s2, _ = add_key(kp, plan="vip", monthly_cap=None)
        a = meter2.check(s2)
        assert a.ok and a.cap is None and a.remaining is None
    print("PASS unconfigured cap fails CLOSED; explicit unlimited (null) honored")


def test_keys_file_never_holds_plaintext():
    with tempfile.TemporaryDirectory() as td:
        kp = Path(td) / "keys.json"
        secret, kid = add_key(kp, label="bob")
        raw = kp.read_text(encoding="utf-8")
        assert secret not in raw, "plaintext secret found at rest!"
        assert kid in raw  # hash (prefix) is what's stored
        rows = list_keys(kp)
        assert rows and rows[0]["key_id"] == kid
        assert all("secret" not in r for r in rows)
    print("PASS keys stored hashed only -- secret absent from keys.json")


def test_month_rollover_resets_count():
    with tempfile.TemporaryDirectory() as td:
        meter, kp, secret, kid = _mk(Path(td))
        for _ in range(3):
            meter.check(secret)
        assert meter.check(secret).reason == "over_cap"
        real = arcaeon_meter._utc_month
        try:
            arcaeon_meter._utc_month = lambda: "2099-01"
            a = meter.check(secret)
            assert a.ok and a.used == 1 and a.month == "2099-01"
        finally:
            arcaeon_meter._utc_month = real
    print("PASS monthly cap is per-month (new month starts at 0)")


def test_usage_and_export_billing_handoff():
    with tempfile.TemporaryDirectory() as td:
        meter, kp, secret, kid = _mk(Path(td))
        s2, kid2 = add_key(kp, plan="pro", monthly_cap=1000, label="carol")
        meter.check(secret)
        meter.check(s2)
        meter.check(s2)
        u = meter.usage(kid2)  # by key_id, not secret
        assert u.used == 2 and u.cap == 1000 and u.label == "carol"
        assert u.key_hash == arcaeon_meter.key_hash(s2)  # full billing identity
        rows = json.loads(meter.export(fmt="json"))
        assert len(rows) == 2  # full roster, zero-usage keys included too
        by_id = {r["key_id"]: r for r in rows}
        assert by_id[kid]["used"] == 1 and by_id[kid2]["used"] == 2
        assert by_id[kid2]["key_hash"] == arcaeon_meter.key_hash(s2)
        assert all(r["key_hash"].startswith(r["key_id"]) for r in rows)
        csv_text = meter.export(fmt="csv")
        lines = csv_text.strip().splitlines()
        assert lines[0] == ("key_id,key_hash,label,plan,used,monthly_cap,"
                            "revoked,month")
        assert len(lines) == 3
        assert secret not in csv_text and s2 not in csv_text
    print("PASS usage(key_id) + export json/csv (full roster, no secrets)")


def test_record_false_peeks_without_increment():
    with tempfile.TemporaryDirectory() as td:
        meter, kp, secret, kid = _mk(Path(td))
        meter.check(secret)
        a = meter.check(secret, record=False)
        assert a.ok and a.used == 1
        assert meter.usage(secret).used == 1  # peek did not count
    print("PASS check(record=False) validates without counting")


def test_ledger_rows_on_grant_and_denial_chain_verifies():
    try:
        from arcaeon_ledger import Ledger
    except ImportError:
        print("SKIP ledger integration (arcaeon-ledger not installed)")
        return
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        lg = d / "usage.log.jsonl"
        kp = d / "keys.json"
        secret, kid = add_key(kp, monthly_cap=1)
        meter = Meter(kp, ledger=lg)
        assert meter.check(secret).ok           # grant -> row
        assert meter.check(secret).reason == "over_cap"  # denial -> row
        rows = list(Ledger(lg))
        assert len(rows) == 2
        assert rows[0]["event"] == "meter.grant" and rows[0]["key_id"] == kid
        assert rows[1]["event"] == "meter.deny" and rows[1]["reason"] == "over_cap"
        assert secret not in lg.read_text(encoding="utf-8")
        v = Ledger(lg).verify()
        assert v.ok and v.rows == 2
    print("PASS ledger option: grant AND denial rows appended, chain verifies, "
          "no secret in the log")


def test_ledger_missing_dep_is_loud():
    import sys
    import unittest.mock as mock
    with tempfile.TemporaryDirectory() as td:
        kp = Path(td) / "keys.json"
        add_key(kp)
        with mock.patch.dict(sys.modules, {"arcaeon_ledger": None}):
            try:
                Meter(kp, ledger=Path(td) / "l.jsonl")
                raise AssertionError("missing soft dep passed silently!")
            except ImportError as e:
                assert "arcaeon-meter[ledger]" in str(e)
    print("PASS ledger= without arcaeon-ledger installed -> loud ImportError")


def test_asgi_middleware_pure_asgi():
    with tempfile.TemporaryDirectory() as td:
        meter, kp, secret, kid = _mk(Path(td))
        cls = meter.asgi_middleware()

        async def inner(scope, receive, send):
            assert scope["arcaeon_meter"].ok
            await send({"type": "http.response.start", "status": 200,
                        "headers": []})
            await send({"type": "http.response.body", "body": b"tool-output"})

        app = cls(inner)

        async def call(auth):
            headers = [(b"authorization", auth)] if auth else []
            scope = {"type": "http", "method": "GET", "path": "/",
                     "headers": headers}
            sent = []
            async def receive():
                return {"type": "http.request"}
            async def send(msg):
                sent.append(msg)
            await app(scope, receive, send)
            return sent

        ok = asyncio.run(call(b"Bearer " + secret.encode()))
        assert ok[0]["status"] == 200 and ok[1]["body"] == b"tool-output"
        no_key = asyncio.run(call(None))
        assert no_key[0]["status"] == 401
        bad = asyncio.run(call(b"Bearer am_wrong"))
        assert bad[0]["status"] == 401
        assert json.loads(bad[1]["body"])["reason"] == "unknown_key"
        # burn the cap (one grant already spent above)
        meter.check(secret)
        meter.check(secret)
        over = asyncio.run(call(b"Bearer " + secret.encode()))
        assert over[0]["status"] == 429
        assert json.loads(over[1]["body"])["reason"] == "over_cap"
        hdrs = dict(over[0]["headers"])
        assert hdrs[b"x-meter-cap"] == b"3"
    print("PASS ASGI middleware: 200 w/ allowance in scope, 401 missing/unknown, "
          "429 over-cap w/ X-Meter-Cap")


def test_cli_add_list_revoke_usage_export():
    from arcaeon_meter.cli import main
    import contextlib
    import io
    with tempfile.TemporaryDirectory() as td:
        kp = str(Path(td) / "keys.json")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["keys", "add", "--keys", kp, "--plan", "free",
                       "--cap", "2", "--label", "dave"])
        assert rc == 0
        out = buf.getvalue()
        secret = [l.split(": ", 1)[1] for l in out.splitlines()
                  if l.startswith("secret: ")][0]
        kid = [l.split(": ", 1)[1] for l in out.splitlines()
               if l.startswith("key_id: ")][0]
        assert secret.startswith("am_") and kid == key_id_of(secret)

        Meter(kp).check(secret)

        for args, want in [
            (["keys", "list", "--keys", kp], kid),
            (["usage", kid, "--keys", kp], "used=1"),
            (["export", "--keys", kp, "--fmt", "csv"], "dave"),
        ]:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                assert main(args) == 0
            assert want in buf.getvalue(), (args, buf.getvalue())
            assert secret not in buf.getvalue()  # secrets never resurface

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            assert main(["keys", "revoke", kid, "--keys", kp]) == 0
        assert f"revoked: {kid}" in buf.getvalue()
        assert Meter(kp).check(secret).reason == "revoked"
    print("PASS CLI keys add/list/revoke + usage + export round-trip")




# --- audit 2026-08-14: fail-closed holes ------------------------------------

def _write_keys(kp: Path, entry: dict) -> str:
    """Hand-write a keys file with an arbitrary entry, return the secret.

    Deliberately bypasses keys.save() — the point is a file that a hand-edit,
    a config generator, or an older release could have produced. save() now
    refuses NaN on the way out; the reader still has to refuse it on the way
    in, because the writer is not the only thing that writes this file.
    """
    from arcaeon_meter.keys import new_secret
    from arcaeon_meter import key_hash
    secret = new_secret()
    kp.write_text(json.dumps({"version": 1, "keys": {key_hash(secret): entry}}),
                  encoding="utf-8")
    return secret


def test_nonsense_cap_is_denied_not_unlimited():
    """`used + cost > cap` is False for NaN and for +Infinity, so a NaN cap
    was a silent unlimited grant -- and json.loads accepts the bare literal
    NaN, so it round-trips through this package's own writer. A cap that is
    not a non-negative int is not a cap."""
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        for label, cap in [("NaN", float("nan")), ("Inf", float("inf")),
                           ("string", "2"), ("list", []), ("negative", -5),
                           ("float", 2.5), ("bool", True)]:
            kp = d / ("keys_" + label + ".json")
            secret = _write_keys(kp, {"plan": "free", "monthly_cap": cap,
                                      "revoked": False})
            m = Meter(kp, db=d / ("u_" + label + ".sqlite3"))
            r = m.check(secret)
            assert not r, "cap=" + label + " GRANTED -- that is unlimited access"
            # NaN/Inf die at the JSON parse (they are not JSON); the rest die
            # at cap resolution. Both are typed denials, which is the claim.
            assert r.reason in ("no_cap_configured", "keys_unreadable"), \
                (label, r.reason)
            if label not in ("NaN", "Inf"):
                assert r.reason == "no_cap_configured", (label, r.reason)
    print("PASS a NaN/Inf/string/negative/float cap fails closed, never unlimited")


def test_nonsense_plan_default_is_denied_not_unlimited():
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        kp = d / "keys.json"
        secret = _write_keys(kp, {"plan": "weird", "revoked": False})
        m = Meter(kp, db=d / "u.sqlite3", plans={"weird": float("nan")})
        r = m.check(secret)
        assert not r and r.reason == "no_cap_configured", r
    print("PASS a nonsense plan default fails closed too")


def test_cost_must_be_a_positive_int():
    """`cost` is a public kwarg and the SQL is `used = used + ?`. A negative
    cost mints budget that persists in SQLite forever; cost=0 is unlimited
    free calls at the cap. Neither one is a metering event."""
    with tempfile.TemporaryDirectory() as td:
        meter, kp, secret, kid = _mk(Path(td))
        for bad in (-1000, 0, 0.4, True, "1", None):
            try:
                meter.check(secret, cost=bad)
                assert False, "cost=" + repr(bad) + " accepted"
            except ValueError:
                pass
        assert meter.usage(kid).used == 0, "a refused cost still moved the counter"
    print("PASS cost must be a positive int; no budget minting, no free calls")


def test_malformed_key_is_a_typed_denial_not_a_crash():
    """A lone surrogate is LEGAL JSON, so any tool reading its key from a
    request body can be handed one. It escaped `except MeterDenied` as a
    UnicodeEncodeError and 500'd instead of 401'ing."""
    with tempfile.TemporaryDirectory() as td:
        meter, kp, secret, kid = _mk(Path(td))
        for bad in (12345, b"am_bytes", ["am_x"], "am_\ud800", {"k": 1}):
            r = meter.check(bad)
            assert not r, repr(bad) + " granted"
            assert r.reason == "malformed_key", (bad, r.reason)

        @meter.metered
        def tool(_meter_key=None):
            return "ran"

        for bad in (12345, "am_\ud800"):
            try:
                tool(_meter_key=bad)
                assert False, "malformed key ran the tool"
            except MeterDenied:
                pass
    print("PASS a malformed key is a typed denial, catchable as MeterDenied")


def test_unreadable_keys_file_is_a_typed_denial():
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        meter, kp, secret, kid = _mk(d)
        assert meter.check(secret)
        for corruption in ('{"version": 1, "keys": {', "[]", "not json at all"):
            kp.write_text(corruption, encoding="utf-8")
            meter._keys_mtime = None          # force a re-read
            r = meter.check(secret)
            assert not r, "granted on corrupt keys file: " + repr(corruption)
            assert r.reason == "keys_unreadable", r.reason
    print("PASS a corrupt/truncated keys file denies, typed, instead of raising")


def test_entry_that_is_not_a_dict_denies():
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        kp = d / "keys.json"
        from arcaeon_meter.keys import new_secret, save
        secret = new_secret()
        save(kp, {"version": 1, "keys": {arcaeon_meter.key_hash(secret): "oops"}})
        m = Meter(kp, db=d / "u.sqlite3")
        r = m.check(secret)
        assert not r and r.reason == "unknown_key", r
    print("PASS a non-dict key entry denies instead of AttributeError")


def test_asgi_never_waves_through_an_unmetered_protocol():
    """websocket scopes skipped the meter entirely -- an unkeyed, uncapped
    streaming endpoint behind middleware whose whole job is the boundary."""
    with tempfile.TemporaryDirectory() as td:
        meter, kp, secret, kid = _mk(Path(td))
        reached = []

        async def app(scope, receive, send):
            reached.append(scope["type"])

        wrapped = meter.asgi_middleware()(app)
        sent = []

        async def send(msg):
            sent.append(msg)

        async def receive():
            return {"type": "websocket.connect"}

        asyncio.run(wrapped({"type": "websocket", "headers": []}, receive, send))
        assert reached == [], "unmetered websocket reached the app: " + str(reached)
        assert sent and sent[0]["type"] == "websocket.close", sent

        asyncio.run(wrapped({"type": "lifespan", "headers": []}, receive, send))
        assert reached == ["lifespan"], "lifespan must still pass through"
    print("PASS a websocket scope is closed, not waved through unmetered")


def test_ledger_failure_rolls_the_count_back():
    """The grant was chained AFTER commit, so a ledger write failure left the
    customer billed for a call that raised before it ran. A retry billed
    again, and verify() reported ok across the gap."""
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        meter, kp, secret, kid = _mk(d, ledger=str(d / "log.jsonl"))
        assert meter.check(secret)
        assert meter.usage(kid).used == 1

        class Boom:
            def append(self, row):
                raise OSError("ledger volume is read-only")

        meter._ledger = Boom()
        try:
            meter.check(secret)
        except OSError:
            pass
        assert meter.usage(kid).used == 1, \
            "counted a call whose ledger row was never written"
    print("PASS a failed ledger write rolls the count back instead of over-billing")


# Two REAL secrets whose sha256 share the first 12 hex, found by brute-force
# birthday search (~27M draws). Nothing is mocked here: these are the actual
# 48-bit collision the old truncated keyspace merged into one billing row.
COLLIDE_A = "am_probe3197488"
COLLIDE_B = "am_probe27007650"
COLLIDE_PREFIX = "fc98907cfe56"


def _collision_keys_file(d: Path) -> Path:
    kp = d / "keys.json"
    kp.write_text(json.dumps({"version": 1, "keys": {
        arcaeon_meter.key_hash(COLLIDE_A): {
            "plan": "pro", "monthly_cap": 1000, "label": "acme-BIG",
            "revoked": False},
        arcaeon_meter.key_hash(COLLIDE_B): {
            "plan": "free", "monthly_cap": 100, "label": "tiny-free",
            "revoked": False},
    }}, indent=2), encoding="utf-8")
    return kp


def test_two_keys_sharing_a_key_id_prefix_bill_separately():
    """The 12-hex key_id is 48 bits. Two customers colliding on it used to
    share one `usage` row: the big one's 900 calls invoiced to BOTH, and the
    free-tier key denied over_cap on its very first call. Counts key on the
    full sha256 now; key_id is a display label."""
    ha, hb = arcaeon_meter.key_hash(COLLIDE_A), arcaeon_meter.key_hash(COLLIDE_B)
    assert ha != hb and ha[:12] == hb[:12] == COLLIDE_PREFIX, "probe keys stale"
    with tempfile.TemporaryDirectory() as td:
        meter = Meter(_collision_keys_file(Path(td)))
        for _ in range(900):
            assert meter.check(COLLIDE_A).ok
        rows = {r["label"]: r for r in json.loads(meter.export())}
        assert rows["acme-BIG"]["used"] == 900
        assert rows["tiny-free"]["used"] == 0, "billed for another key's calls"
        # both display the same key_id, so the invoice identity is key_hash
        assert rows["acme-BIG"]["key_id"] == rows["tiny-free"]["key_id"]
        assert rows["acme-BIG"]["key_hash"] != rows["tiny-free"]["key_hash"]
        assert meter.usage(COLLIDE_B).used == 0
        assert meter.check(COLLIDE_B).ok, "cap polluted by the other key"
        assert meter.usage(COLLIDE_A).used == 900
    print("PASS two keys sharing a 12-hex key_id count and bill SEPARATELY")


def test_pre_0_1_2_db_migrates_what_it_can_and_strands_what_it_cannot():
    """Old rows keyed on the 12-hex prefix. One roster match is provably that
    key's usage and carries over; a prefix matching two keys (or none) cannot
    be split by anyone, so it is preserved as legacy — never billed, never
    silently dropped."""
    import sqlite3
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        kp = _collision_keys_file(d)
        solo, solo_kid = add_key(kp, plan="pro", monthly_cap=1000, label="solo")
        db = d / "keys_usage.sqlite3"
        con = sqlite3.connect(db, isolation_level=None)
        con.execute("CREATE TABLE usage (key_id TEXT NOT NULL, "
                    "month TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0, "
                    "PRIMARY KEY (key_id, month))")
        con.executemany("INSERT INTO usage VALUES (?,?,?)", [
            (solo_kid, "2026-08", 42),        # one roster match -> recoverable
            (COLLIDE_PREFIX, "2026-08", 900),  # two matches -> unattributable
            ("deadbeef0000", "2026-08", 7),    # no match -> unattributable
        ])
        con.close()

        meter = Meter(kp)   # migration runs on open
        assert meter.usage(solo, month="2026-08").used == 42, "lost real usage"
        # the merged row is not handed to either colliding key
        assert meter.usage(COLLIDE_A, month="2026-08").used == 0
        assert meter.usage(COLLIDE_B, month="2026-08").used == 0
        stranded = {r["legacy_key_id"]: r["used"]
                    for r in meter.legacy_usage(month="2026-08")}
        assert stranded == {COLLIDE_PREFIX: 900, "deadbeef0000": 7}, stranded
        # nothing unattributable leaks into an invoice
        assert all(r["used"] in (0, 42)
                   for r in json.loads(meter.export(month="2026-08")))
        # the original table is kept for forensics, not dropped
        con = sqlite3.connect(db)
        try:
            names = {r[0] for r in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            assert "usage_pre_0_1_2" in names, names
            assert con.execute("SELECT SUM(used) FROM usage_pre_0_1_2"
                               ).fetchone()[0] == 949
        finally:
            con.close()
        # idempotent: reopening does not re-migrate or double-count
        assert Meter(kp).usage(solo, month="2026-08").used == 42
    print("PASS pre-0.1.2 migration: single-match rows recovered, merged and "
          "orphaned rows stranded as legacy (never billed)")


def test_migration_refuses_to_run_without_a_readable_roster():
    """Migrating blind would zero every recoverable count — i.e. hand every
    customer their budget back. Fail loud instead."""
    import sqlite3
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        kp = d / "keys.json"
        secret, kid = add_key(kp, monthly_cap=100)
        db = d / "keys_usage.sqlite3"
        con = sqlite3.connect(db, isolation_level=None)
        con.execute("CREATE TABLE usage (key_id TEXT NOT NULL, "
                    "month TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0, "
                    "PRIMARY KEY (key_id, month))")
        con.execute("INSERT INTO usage VALUES (?,?,?)", (kid, "2026-08", 5))
        con.close()
        kp.write_text("{not json", encoding="utf-8")
        try:
            Meter(kp)
            assert False, "migrated against an unreadable keys file"
        except RuntimeError as e:
            assert "truncated keyspace" in str(e)
    print("PASS migration fails loud when the keys roster cannot be read")


def test_commit_failure_after_ledger_append_chains_a_void():
    """The other side of the ledger/SQLite seam: the grant row is chained,
    then COMMIT fails, so SQLite has no such grant. The chained row cannot be
    removed — so its inverse is chained. The receipt invariant becomes
    grants MINUS voids == the billed count, and survives the half-write."""
    try:
        from arcaeon_ledger import Ledger
    except ImportError:
        print("SKIP commit-failure void (arcaeon-ledger not installed)")
        return
    import sqlite3
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        lg = d / "log.jsonl"
        meter, kp, secret, kid = _mk(d, ledger=str(lg))
        assert meter.check(secret).ok

        real_connect = meter._connect

        class CommitFails:
            def __init__(self, con):
                self._con = con

            def execute(self, sql, *a):
                if sql.strip().upper().startswith("COMMIT"):
                    raise sqlite3.OperationalError("disk I/O error")
                return self._con.execute(sql, *a)

            def close(self):
                self._con.close()   # uncommitted work rolls back

        meter._connect = lambda: CommitFails(real_connect())
        try:
            meter.check(secret)
            assert False, "a failed COMMIT must not look like a grant"
        except sqlite3.OperationalError:
            pass
        meter._connect = real_connect

        assert meter.usage(kid).used == 1, "counted an uncommitted grant"
        rows = list(Ledger(lg))
        events = [r["event"] for r in rows]
        assert events == ["meter.grant", "meter.grant", "meter.void"], events
        assert rows[-1]["reason"] == "commit_failed"
        grants = sum(1 for r in rows if r["event"] == "meter.grant")
        voids = sum(1 for r in rows if r["event"] == "meter.void")
        assert grants - voids == meter.usage(kid).used == 1
        assert Ledger(lg).verify().ok   # chain intact, nothing removed
    print("PASS a COMMIT failure after the ledger append chains a void: "
          "grants - voids still equals the billed count")


def test_asgi_does_not_bill_a_cors_preflight():
    """An OPTIONS preflight is the browser asking whether it may call. It
    carries no Authorization header, so metering it both billed a non-call
    and answered 401 — which breaks the CORS handshake it was inspecting."""
    with tempfile.TemporaryDirectory() as td:
        meter, kp, secret, kid = _mk(Path(td))
        seen = []

        async def inner(scope, receive, send):
            seen.append((scope["method"], scope["arcaeon_meter"]))
            await send({"type": "http.response.start", "status": 204,
                        "headers": []})
            await send({"type": "http.response.body", "body": b""})

        def call(app, method, auth=None):
            scope = {"type": "http", "method": method, "path": "/",
                     "headers": [(b"authorization", auth)] if auth else []}
            sent = []

            async def receive():
                return {"type": "http.request"}

            async def send(msg):
                sent.append(msg)

            asyncio.run(app(scope, receive, send))
            return sent

        app = meter.asgi_middleware()(inner)
        pre = call(app, "OPTIONS")                       # no bearer, as browsers send
        assert pre[0]["status"] == 204, pre[0]["status"]  # reached the app, not a 401
        assert seen[-1] == ("OPTIONS", None)
        assert meter.usage(kid).used == 0, "billed a CORS preflight"

        # a real call still bills, and HEAD is billed by default (documented)
        call(app, "GET", b"Bearer " + secret.encode())
        call(app, "HEAD", b"Bearer " + secret.encode())
        assert meter.usage(kid).used == 2, meter.usage(kid).used

        # ...and the policy is the operator's to widen
        app2 = meter.asgi_middleware(skip_methods=("OPTIONS", "HEAD"))(inner)
        call(app2, "HEAD", b"Bearer " + secret.encode())
        assert meter.usage(kid).used == 2, "skip_methods ignored"
    print("PASS ASGI bills real calls only: CORS preflight passes through "
          "unmetered, HEAD billable but skippable")


def test_empty_identifier_never_resolves_to_a_key():
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        meter, kp, secret, kid = _mk(d)
        for bad in ("", "a", "abc"):
            try:
                revoke_key(kp, bad)
                assert False, "revoked a key by prefix " + repr(bad)
            except KeyError:
                pass
            try:
                meter.usage(bad)
                assert False, "reported usage for prefix " + repr(bad)
            except KeyError:
                pass
    print("PASS a short/empty key_id prefix never resolves to an arbitrary key")


def test_concurrent_revoke_is_not_erased_by_a_concurrent_add():
    """add_key and revoke_key are load-mutate-save with no lock, so a
    concurrent add rewrote the whole document from a stale read and silently
    un-revoked the key -- while the CLI reported the revocation succeeded."""
    import threading
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        kp = d / "keys.json"
        secret, kid = add_key(kp, plan="free", monthly_cap=5)
        errors = []

        def adder(n):
            try:
                for _ in range(n):
                    add_key(kp, plan="free", monthly_cap=5)
            except Exception as e:      # noqa: BLE001
                errors.append(e)

        threads = [threading.Thread(target=adder, args=(15,)) for _ in range(4)]
        for t in threads:
            t.start()
        revoke_key(kp, kid)
        for t in threads:
            t.join()
        assert not errors, "concurrent writers crashed: " + str(errors[:2])
        entries = {r["key_id"]: r for r in list_keys(kp)}
        assert len(entries) == 61, "lost writes: expected 61 keys, got " + str(len(entries))
        assert entries[kid]["revoked"] is True, "the revocation was erased"
        m = Meter(kp, db=d / "u.sqlite3")
        assert not m.check(secret), "a revoked key is still spending"
    print("PASS a revocation survives concurrent key adds; no lost writes")


if __name__ == "__main__":
    test_three_line_promise_and_grant_path()
    test_over_cap_denied_typed_never_silent()
    test_revoked_key_denied()
    test_unknown_and_missing_key_denied()
    test_unconfigured_cap_fails_closed()
    test_keys_file_never_holds_plaintext()
    test_month_rollover_resets_count()
    test_usage_and_export_billing_handoff()
    test_record_false_peeks_without_increment()
    test_ledger_rows_on_grant_and_denial_chain_verifies()
    test_ledger_missing_dep_is_loud()
    test_asgi_middleware_pure_asgi()
    test_cli_add_list_revoke_usage_export()
    test_nonsense_cap_is_denied_not_unlimited()
    test_nonsense_plan_default_is_denied_not_unlimited()
    test_cost_must_be_a_positive_int()
    test_malformed_key_is_a_typed_denial_not_a_crash()
    test_unreadable_keys_file_is_a_typed_denial()
    test_entry_that_is_not_a_dict_denies()
    test_asgi_never_waves_through_an_unmetered_protocol()
    test_ledger_failure_rolls_the_count_back()
    test_two_keys_sharing_a_key_id_prefix_bill_separately()
    test_pre_0_1_2_db_migrates_what_it_can_and_strands_what_it_cannot()
    test_migration_refuses_to_run_without_a_readable_roster()
    test_commit_failure_after_ledger_append_chains_a_void()
    test_asgi_does_not_bill_a_cors_preflight()
    test_empty_identifier_never_resolves_to_a_key()
    test_concurrent_revoke_is_not_erased_by_a_concurrent_add()
    print("ALL PASS")
