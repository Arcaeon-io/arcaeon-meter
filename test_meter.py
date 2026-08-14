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
        rows = json.loads(meter.export(fmt="json"))
        assert len(rows) == 2  # full roster, zero-usage keys included too
        by_id = {r["key_id"]: r for r in rows}
        assert by_id[kid]["used"] == 1 and by_id[kid2]["used"] == 2
        csv_text = meter.export(fmt="csv")
        lines = csv_text.strip().splitlines()
        assert lines[0] == "key_id,label,plan,used,monthly_cap,revoked,month"
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
    print("ALL PASS")
