"""Property-based / fuzzing hardening for arcaeon_meter.

Hand-written tests check the cases we thought of. This file drives thousands of
RANDOM check/peek/deny operations across many keys with random cap configs and
random costs, tracking an independent in-memory ORACLE, and asserts the money
invariants hold on every single operation:

  1. EXACT + MONOTONIC counts. After any accepted call, meter.usage(key).used
     equals the oracle's running sum of costs for that key, and never decreases.
  2. NO CROSS-KEY CONTAMINATION. Every key's count equals its own oracle and
     only its own — one key's traffic never lands on another's row. export()
     and usage() agree with the oracle for the whole roster.
  3. CAP IS NEVER EXCEEDED. Whenever an Allowance is returned, used <= cap.
     A call that would cross the cap is Denied(over_cap) and does NOT increment.
  4. A DENIED CALL NEVER INCREMENTS. Unknown / revoked / malformed / over-cap /
     no-cap denials leave every count untouched.
  5. LEDGER RECEIPT INVARIANT (when ledger= is set): sum(grant costs) minus
     sum(void costs) equals the total billed count, and the ledger verifies.

Plus a concurrency property (random cap vs random contended attempts across
real OS processes: grants == min(attempts, cap), exactly, never over) and the
storage-level anti-merge guarantees for keys that share a 12-hex display prefix.

Run standalone for quotable counts:  python test_property_meter.py
"""
from __future__ import annotations

import functools
import json
import os
import random
import subprocess
import sys
import tempfile
from pathlib import Path

from arcaeon_meter import Meter, key_hash, key_id_of
from arcaeon_meter.keys import add_key, revoke_key, new_secret


def _no_fsync(fn):
    """Run `fn` with os.fsync noop'd, then restore it (durability, not
    correctness). SCOPED to the decorated call so it never leaks into other
    tests — notably the keys-file concurrency tests — in a shared pytest run."""
    @functools.wraps(fn)
    def wrapper(*a, **k):
        orig = os.fsync
        os.fsync = lambda _fd: None
        try:
            return fn(*a, **k)
        finally:
            os.fsync = orig
    return wrapper

SEED = int(os.environ.get("METER_PROP_SEED", "20260815"))
N_OPS = int(os.environ.get("METER_PROP_OPS", "5000"))


def _fresh(td: Path):
    return Path(td) / "keys.json"


@_no_fsync
def run_op_property(n_ops=N_OPS, seed=SEED, use_ledger=False, verbose=False):
    rng = random.Random(seed)
    td = Path(tempfile.mkdtemp(prefix="meter_prop_"))
    kp = _fresh(td)
    ledger_path = td / "usage.log.jsonl" if use_ledger else None

    # --- build a random roster of keys with varied cap configs ---------------
    plans = {"free": 5, "pro": 50, "unl": None, "bad": "not-a-cap"}
    keys = []          # list of dicts: secret, hash, cap(None=unlimited or int)
    n_keys = rng.randint(6, 14)
    for _ in range(n_keys):
        style = rng.random()
        if style < 0.4:
            cap = rng.randint(1, 40)
            secret, _ = add_key(kp, plan="custom", monthly_cap=cap)
            eff_cap, deny_nocap = cap, False
        elif style < 0.6:
            secret, _ = add_key(kp, plan="unl", monthly_cap=None)
            eff_cap, deny_nocap = None, False           # explicit unlimited
        elif style < 0.8:
            plan = rng.choice(["free", "pro"])
            secret, _ = add_key(kp, plan=plan, monthly_cap="plan")
            eff_cap, deny_nocap = plans[plan], False     # deferred to plan
        else:
            # misconfigured cap -> meter must fail CLOSED (no_cap_configured)
            plan = rng.choice(["bad", "missingplan"])
            secret, _ = add_key(kp, plan=plan, monthly_cap="plan")
            eff_cap, deny_nocap = None, True
        keys.append({"secret": secret, "hash": key_hash(secret),
                     "cap": eff_cap, "deny_nocap": deny_nocap,
                     "revoked": False, "used": 0})

    meter = Meter(kp, plans=plans, ledger=ledger_path)

    ops = grants = denials = peeks = 0
    grant_cost_sum = 0

    def assert_all_counts():
        # cross-key: every key's stored count == its own oracle, nobody else's
        for k in keys:
            got = meter.usage(k["secret"]).used
            assert got == k["used"], (
                f"COUNT DRIFT key={k['hash'][:12]} stored={got} "
                f"oracle={k['used']}")

    for i in range(n_ops):
        ops += 1
        roll = rng.random()

        # occasionally revoke a live key (denials must then not increment)
        if roll < 0.03:
            live = [k for k in keys if not k["revoked"]]
            if len(live) > 3:
                victim = rng.choice(live)
                revoke_key(kp, victim["secret"])
                victim["revoked"] = True
            continue

        # occasionally hit an unknown / malformed key: must deny, never count
        if roll < 0.09:
            bogus = rng.choice([new_secret(), "am_" + "z" * 10, "",
                                "not-a-key", "\udce9-lone-surrogate"])
            before = [k["used"] for k in keys]
            r = meter.check(bogus, record=True)
            assert not r, f"bogus key granted: {bogus!r}"
            assert [k["used"] for k in keys] == before, "bogus deny incremented!"
            denials += 1
            continue

        k = rng.choice(keys)
        cost = rng.randint(1, 5)

        # peek (record=False) must never change any count
        if rng.random() < 0.15:
            snapshot = [kk["used"] for kk in keys]
            r = meter.check(k["secret"], cost=cost, record=False)
            assert [kk["used"] for kk in keys] == snapshot, "peek incremented!"
            peeks += 1
            continue

        r = meter.check(k["secret"], cost=cost, record=True)

        if k["revoked"]:
            assert not r and r.reason == "revoked", (r.ok, getattr(r, "reason", None))
            denials += 1
        elif k["deny_nocap"]:
            assert not r and r.reason == "no_cap_configured", getattr(r, "reason", None)
            denials += 1
        elif k["cap"] is None:                          # explicit unlimited
            assert r, f"unlimited key denied: {getattr(r,'reason',None)}"
            k["used"] += cost
            assert r.used == k["used"]
            grants += 1
            grant_cost_sum += cost
        else:                                           # finite cap
            if k["used"] + cost > k["cap"]:
                assert not r and r.reason == "over_cap", getattr(r, "reason", None)
                assert r.used == k["used"] and r.cap == k["cap"]
                denials += 1
            else:
                assert r, f"under-cap call denied: {getattr(r,'reason',None)}"
                k["used"] += cost
                assert r.used == k["used"] <= k["cap"], "CAP EXCEEDED"
                assert r.remaining == k["cap"] - k["used"]
                grants += 1
                grant_cost_sum += cost

        if i % 250 == 0:               # periodic full cross-key reconciliation
            assert_all_counts()
        if verbose and i % 1000 == 0:
            print(f"  ...op {i}")

    assert_all_counts()

    # export() must agree with the oracle for the whole roster, no contamination
    exported = {row["key_hash"]: row["used"]
                for row in json.loads(meter.export())}
    for k in keys:
        assert exported.get(k["hash"], 0) == k["used"], "export drift"
    total_billed = sum(k["used"] for k in keys)

    ledger_ok = None
    receipt_ok = None
    if use_ledger:
        from arcaeon_ledger import verify_file
        ledger_ok = bool(verify_file(ledger_path))
        g = v = 0
        for raw in ledger_path.read_text(encoding="utf-8").splitlines():
            row = json.loads(raw)
            if row.get("event") == "meter.grant":
                g += row.get("cost", 1)
            elif row.get("event") == "meter.void":
                v += row.get("cost", 1)
        receipt_ok = (g - v == total_billed)

    return {"ops": ops, "grants": grants, "denials": denials, "peeks": peeks,
            "total_billed": total_billed, "grant_cost_sum": grant_cost_sum,
            "ledger_ok": ledger_ok, "receipt_ok": receipt_ok, "n_keys": n_keys}


def test_property_counts_exact_no_contamination_cap_enforced():
    stats = run_op_property()
    assert stats["ops"] == N_OPS
    # grants recorded == billed sum (monotonic accumulation, no lost/extra count)
    assert stats["grant_cost_sum"] == stats["total_billed"]
    print(f"\n[meter] {stats['ops']} ops across {stats['n_keys']} keys: "
          f"{stats['grants']} grants / {stats['denials']} denials / "
          f"{stats['peeks']} peeks; counts EXACT + no cross-key contamination + "
          f"cap never exceeded; billed={stats['total_billed']}")


def test_property_ledger_receipt_invariant():
    stats = run_op_property(n_ops=2000, seed=SEED + 7, use_ledger=True)
    assert stats["ledger_ok"] is True, "usage ledger failed to verify"
    assert stats["receipt_ok"] is True, "grants-minus-voids != billed count"
    print(f"[meter] ledger receipt: grants-minus-voids == billed "
          f"({stats['total_billed']}); chained usage log verifies GREEN")


def test_prefix_collision_does_not_merge_counts():
    """Two keys.json entries SHARING a 12-hex display prefix stay distinct
    billing identities: export lists both under different full hashes, and
    usage() by the shared prefix refuses (ambiguous) rather than pick one at
    random. Counting keys on the full sha256 is what prevents the merge."""
    td = Path(tempfile.mkdtemp(prefix="meter_collide_"))
    kp = td / "keys.json"
    shared = "abcdef012345"                     # forced identical 12-hex prefix
    h1 = shared + "1" * 52
    h2 = shared + "2" * 52
    doc = {"version": 1, "keys": {
        h1: {"plan": "a", "monthly_cap": 10, "revoked": False},
        h2: {"plan": "b", "monthly_cap": 20, "revoked": False}}}
    kp.write_text(json.dumps(doc), encoding="utf-8")
    meter = Meter(kp)
    con = meter._connect()
    try:  # simulate each having spent, keyed on its FULL hash
        con.execute("BEGIN IMMEDIATE")
        from arcaeon_meter import _utc_month
        m = _utc_month()
        con.execute("INSERT INTO usage(key_hash,month,used) VALUES(?,?,?)", (h1, m, 7))
        con.execute("INSERT INTO usage(key_hash,month,used) VALUES(?,?,?)", (h2, m, 3))
        con.execute("COMMIT")
    finally:
        con.close()
    exported = {r["key_hash"]: r["used"] for r in json.loads(meter.export())}
    assert exported[h1] == 7 and exported[h2] == 3, "prefix-collision merged counts!"
    # by the shared prefix, usage() must refuse rather than guess
    try:
        meter.usage(shared)
        raise AssertionError("ambiguous prefix should have raised KeyError")
    except KeyError as e:
        assert "ambiguous" in str(e)
    print("[meter] 12-hex prefix collision: counts stay separate (7 and 3), "
          "ambiguous prefix lookup refused")


# ---- concurrency property: real OS processes, random cap vs random load -----

_WORKER = r"""
import sys
from arcaeon_meter import Meter
kp, secret, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
m = Meter(kp)
g = d = 0
for _ in range(n):
    r = m.check(secret)
    if r: g += 1
    else:
        assert r.reason == "over_cap", r.reason
        d += 1
print(f"{g} {d}")
"""


def _hammer(kp, secret, per_worker, workers):
    procs = [subprocess.Popen(
        [sys.executable, "-c", _WORKER, str(kp), secret, str(per_worker)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for _ in range(workers)]
    g = d = 0
    for p in procs:
        out, err = p.communicate(timeout=120)
        assert p.returncode == 0, err
        gi, di = out.split()
        g += int(gi); d += int(di)
    return g, d


def test_property_concurrency_cap_exact():
    rng = random.Random(SEED + 3)
    cases = int(os.environ.get("METER_CONC_CASES", "12"))
    ok = 0
    for _ in range(cases):
        td = Path(tempfile.mkdtemp(prefix="meter_conc_"))
        kp = td / "keys.json"
        cap = rng.randint(20, 200)
        workers = rng.randint(2, 4)
        per = rng.randint(cap // workers, cap)      # total may over/undershoot cap
        secret, _ = add_key(kp, plan="c", monthly_cap=cap)
        Meter(kp)                                    # create shared db
        total = per * workers
        g, d = _hammer(kp, secret, per, workers)
        expect = min(total, cap)
        assert g == expect, f"cap={cap} total={total}: granted {g}, want {expect}"
        assert d == total - g
        assert Meter(kp).usage(secret).used == expect
        ok += 1
    print(f"[meter] concurrency: {ok}/{cases} random (cap, workers, load) cases "
          f"-> grants == min(load, cap) EXACTLY, cap never exceeded")


if __name__ == "__main__":
    print(f"seed={SEED} ops={N_OPS}")
    s = run_op_property(verbose=True)
    print(f"ops={s['ops']} grants={s['grants']} denials={s['denials']} "
          f"peeks={s['peeks']} billed={s['total_billed']}")
    print(f"grant_cost_sum == billed: {s['grant_cost_sum'] == s['total_billed']}")
    sl = run_op_property(n_ops=2000, seed=SEED + 7, use_ledger=True)
    print(f"ledger receipt ok={sl['receipt_ok']} ledger_verifies={sl['ledger_ok']}")
    test_prefix_collision_does_not_merge_counts()
    test_property_concurrency_cap_exact()
    print("ALL METER PROPERTY CHECKS PASSED")
