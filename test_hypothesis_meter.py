# SPDX-License-Identifier: MIT
"""Hypothesis-driven property tests for arcaeon_meter.

Distinct in MECHANISM from `test_property_meter.py` (a hand-rolled seeded
`random`-module fuzzer with an in-memory oracle): this file drives
`@given` + `st.` strategies through Hypothesis's own example generation and
shrinking, so a failure here reports as a minimal reproducing case, not a
5000-op trace. Where an invariant overlaps with the existing fuzzer (money
accounting, prefix-collision safety) that is deliberate — the point is an
independently-generated second opinion on the same claims, not new claims.

Covers, per the audit brief:
  1. Usage-record aggregation determinism + export()/usage() agreement.
  2. Key-hash collision resistance (the 0.1.2 48-bit key_id fix).
  3. The unicode-line-separator-class bug (U+0085 / U+2028 / U+2029).
  4. Fails-closed: malformed/ambiguous input always denies, never grants.

Run standalone: `pytest test_hypothesis_meter.py -q`
Stress (dev only): `METER_HYP_EXAMPLES=400 pytest test_hypothesis_meter.py -q`
"""
from __future__ import annotations

import json
import os
import string
import tempfile
from pathlib import Path

from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from arcaeon_meter import Allowance, Denied, Meter, key_hash, key_id_of
from arcaeon_meter.keys import add_key, list_keys, load

# Checked-in default is CI-reasonable (60-100/property per the sibling repos'
# convention). Bumped to 300-500 during development to hunt for shrinkable
# failures before settling here — see the report for what that surfaced.
EXAMPLES = int(os.environ.get("METER_HYP_EXAMPLES", "80"))

_settings = settings(max_examples=EXAMPLES, deadline=None,
                     suppress_health_check=[HealthCheck.too_slow,
                                            HealthCheck.data_too_large])


def _write_raw_keys(path: Path, doc: dict) -> None:
    """Write a keys.json bypassing `keys.save()` — for planting shapes the
    package's own writer would refuse (NaN caps, non-dict entries), the way
    a hand-edited or foreign-tool-written file could arrive in the wild."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, ensure_ascii=False, allow_nan=True),
                    encoding="utf-8")


# ===========================================================================
# 1. Usage-record aggregation determinism + export()/usage() agreement
# ===========================================================================

# A fixed, deterministic roster (not add_key()'s random secrets) so the same
# op sequence can be replayed against two INDEPENDENT fresh databases and the
# final state compared byte-for-byte.
_ROSTER_SIZE = 4
_ROSTER_SECRETS = [f"am_hyp_fixture_key_{i}" for i in range(_ROSTER_SIZE)]
_ROSTER_CAP = 6  # small and finite on purpose: forces real over_cap denials
                 # into the op sequence, so determinism is exercised across
                 # the grant AND the deny path, not just the grant path.

_ops_strategy = st.lists(
    st.tuples(
        st.integers(min_value=0, max_value=_ROSTER_SIZE - 1),  # which key
        st.integers(min_value=1, max_value=5),                  # cost
        st.booleans(),                                          # record?
    ),
    min_size=0, max_size=40,
)


def _fresh_roster(td: Path) -> Path:
    kp = td / "keys.json"
    doc = {"version": 1, "keys": {
        key_hash(s): {"plan": "fixed", "monthly_cap": _ROSTER_CAP,
                      "revoked": False}
        for s in _ROSTER_SECRETS}}
    _write_raw_keys(kp, doc)
    return kp


def _replay(ops, td: Path) -> "dict[str, int]":
    kp = _fresh_roster(td)
    meter = Meter(kp)
    for idx, cost, record in ops:
        meter.check(_ROSTER_SECRETS[idx], cost=cost, record=record)
    return {key_hash(s): meter.usage(s).used for s in _ROSTER_SECRETS}, meter


@given(ops=_ops_strategy)
@_settings
def test_replaying_identical_ops_against_fresh_db_is_deterministic(ops):
    """The same operation sequence (random keys, costs, record flags, order)
    replayed against two INDEPENDENT fresh meter instances must land on
    identical final per-key counts — no ordering-dependent nondeterminism in
    the check-then-increment path, across both grants and over_cap denials."""
    with tempfile.TemporaryDirectory() as td_a, tempfile.TemporaryDirectory() as td_b:
        counts_a, _ = _replay(ops, Path(td_a))
        counts_b, _ = _replay(ops, Path(td_b))
        assert counts_a == counts_b, (
            f"same op sequence produced different final counts: "
            f"{counts_a} vs {counts_b}")


@given(ops=_ops_strategy)
@_settings
def test_export_totals_equal_usage_per_key_sums_no_double_count_no_drop(ops):
    """export()'s per-row `used` must equal usage()'s per-key reading for
    every key in the roster, every key in the roster must appear exactly
    once (no drop, no duplicate row), and the sum across export() rows must
    equal the sum across independent usage() calls — generalizes the
    existing fuzzer's identical claim via Hypothesis's own generation."""
    with tempfile.TemporaryDirectory() as td:
        counts, meter = _replay(ops, Path(td))
        exported = json.loads(meter.export())
        assert len(exported) == _ROSTER_SIZE, "export() dropped or duplicated a roster row"
        exported_by_hash = {row["key_hash"]: row["used"] for row in exported}
        assert set(exported_by_hash) == set(counts), "export()/usage() key sets disagree"
        for h, used in counts.items():
            assert exported_by_hash[h] == used, (
                f"export() used={exported_by_hash[h]} != usage() used={used} for {h[:12]}")
        assert sum(exported_by_hash.values()) == sum(counts.values())


# ===========================================================================
# 2. Key-hash collision resistance — the 0.1.2 48-bit key_id fix
# ===========================================================================

_hex12 = st.text(alphabet="0123456789abcdef", min_size=12, max_size=12)
_hex52 = st.text(alphabet="0123456789abcdef", min_size=52, max_size=52)


@given(shared_prefix=_hex12, suffix_a=_hex52, suffix_b=_hex52,
      used_a=st.integers(min_value=0, max_value=10_000),
      used_b=st.integers(min_value=0, max_value=10_000))
@_settings
def test_full_hash_collision_shape_never_merges_counts(
        shared_prefix, suffix_a, suffix_b, used_a, used_b):
    """Generalizes `test_property_meter.py::test_prefix_collision_does_not_merge_counts`
    (one hardcoded pair) into a Hypothesis property over MANY generated pairs
    that share the vulnerable 12-hex `key_id` prefix but differ in their
    full sha256 — the exact shape 0.1.2's full-sha256 keying fix defends
    against. NOTE (test-construction honesty): the two full hashes here are
    HAND-CONSTRUCTED strings, not sha256 outputs of real secrets — finding an
    actual preimage pair sharing a 12-hex prefix by brute force is
    intractable per-example. This mirrors the existing hardcoded test's own
    construction; it exercises the storage/lookup layer (does the DB and
    export ever conflate two full hashes that share a display prefix), which
    is exactly what the 0.1.2 bug was — a storage-layer collapse, not a
    hash-function weakness."""
    assume(suffix_a != suffix_b)
    h1, h2 = shared_prefix + suffix_a, shared_prefix + suffix_b
    assert h1[:12] == h2[:12] == shared_prefix
    assert h1 != h2
    with tempfile.TemporaryDirectory() as td:
        kp = Path(td) / "keys.json"
        doc = {"version": 1, "keys": {
            h1: {"plan": "a", "monthly_cap": 10_000, "revoked": False},
            h2: {"plan": "b", "monthly_cap": 10_000, "revoked": False}}}
        _write_raw_keys(kp, doc)
        meter = Meter(kp)
        from arcaeon_meter import _utc_month
        con = meter._connect()
        try:
            con.execute("BEGIN IMMEDIATE")
            m = _utc_month()
            con.execute("INSERT INTO usage(key_hash,month,used) VALUES(?,?,?)", (h1, m, used_a))
            con.execute("INSERT INTO usage(key_hash,month,used) VALUES(?,?,?)", (h2, m, used_b))
            con.execute("COMMIT")
        finally:
            con.close()
        exported = {r["key_hash"]: r["used"] for r in json.loads(meter.export())}
        assert exported[h1] == used_a, "collision merged h1's count"
        assert exported[h2] == used_b, "collision merged h2's count"
        # An ambiguous prefix lookup must refuse, never silently pick one.
        try:
            meter.usage(shared_prefix)
            raise AssertionError("ambiguous prefix should have raised KeyError")
        except KeyError as e:
            assert "ambiguous" in str(e)


@given(s=st.text(min_size=0, max_size=200))
@_settings
def test_key_hash_same_input_same_output(s):
    assert key_hash(s) == key_hash(s)
    assert key_id_of(s) == key_id_of(s) == key_hash(s)[:12]


@given(s=st.text(min_size=0, max_size=200))
@_settings
def test_key_hash_output_format_invariants(s):
    h = key_hash(s)
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)
    kid = key_id_of(s)
    assert len(kid) == 12
    assert h.startswith(kid)


@given(a=st.text(min_size=0, max_size=200), b=st.text(min_size=0, max_size=200))
@_settings
def test_key_hash_different_inputs_different_outputs(a, b):
    """Different str inputs -> different sha256 hex, with overwhelming
    probability across hundreds of generated cases. This is a genuine
    property of sha256 (str != str => distinct UTF-8 bytes => a real hash
    collision would be required to fail, not merely a coincidence), not a
    statistical hope."""
    assume(a != b)
    assert key_hash(a) != key_hash(b)


# ===========================================================================
# 3. The unicode-line-separator-class bug (U+0085 / U+2028 / U+2029)
# ===========================================================================
#
# VERDICT (checked both the direct-I/O path and the optional ledger path):
#
# ABSENT in arcaeon_meter's own storage. `grep -n "splitlines\|readlines"
# arcaeon_meter/*.py` returns nothing — keys.json is written and read as ONE
# JSON document (`json.dump`/`json.loads` over the whole file text), never
# split into lines. The bug class requires a writer that skips escaping
# these characters (`ensure_ascii=False`, which keys.py's save() DOES use)
# PLUS a reader that treats them as row boundaries (`.splitlines()`), and
# meter's own keys-file reader is the former without the latter — there is
# no line-boundary concept to corrupt in a single-document JSON file.
#
# FIXED (transitively) on the optional `ledger=` path. `Meter._log()` chains
# rows through `arcaeon_ledger.Ledger.append()`; `Ledger.__iter__` used to
# read with `.splitlines()` (the exact vulnerable idiom) and was fixed in
# arcaeon-ledger 0.5.6 (see that package's CHANGELOG, "U+2028-class
# sealed-but-unverifiable bug") to split on literal "\n" only. The
# currently-installed arcaeon-ledger is 0.5.6 (confirmed via
# `importlib.metadata` at test-collection time below), so meter's ledger
# integration inherits the fix, not the bug. Both claims are pinned as live
# tests, not just asserted in prose.

_LINE_SEP_CLASS = ["\u0085", "\u2028", "\u2029"]  # NEL, LINE SEP, PARA SEP
_safe_text = st.text(alphabet=string.ascii_letters + string.digits + " ", max_size=12)


def test_installed_ledger_version_is_the_fixed_one():
    import arcaeon_ledger
    # Parsed, not string-compared, so a future 0.5.10 doesn't false-fail here.
    major, minor, patch = (int(x) for x in arcaeon_ledger.__version__.split(".")[:3])
    assert (major, minor, patch) >= (0, 5, 6), (
        f"arcaeon-ledger {arcaeon_ledger.__version__} predates the 0.5.6 "
        f"U+2028-class fix — meter's ledger=... path would inherit the bug")


@given(chars=st.lists(st.sampled_from(_LINE_SEP_CLASS), min_size=1, max_size=5),
      prefix=_safe_text, suffix=_safe_text)
@_settings
def test_unicode_line_sep_class_survives_keys_json_roundtrip(chars, prefix, suffix):
    label = prefix + "".join(chars) + suffix
    with tempfile.TemporaryDirectory() as td:
        kp = Path(td) / "keys.json"
        secret, _ = add_key(kp, plan="free", monthly_cap=10, label=label)
        h = key_hash(secret)
        # Reload via the package's own reader (whole-file json.loads).
        doc = load(kp)
        assert doc["keys"][h]["label"] == label, "label corrupted on disk round-trip"
        rows = [r for r in list_keys(kp) if r["key_hash"] == h]
        assert len(rows) == 1 and rows[0]["label"] == label
        meter = Meter(kp)
        result = meter.check(secret)
        assert result and result.ok, "a key with unicode-line-sep-class label failed to check"


@given(chars=st.lists(st.sampled_from(_LINE_SEP_CLASS), min_size=1, max_size=5))
@settings(max_examples=min(EXAMPLES, 40), deadline=None,
         suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
def test_unicode_line_sep_class_survives_ledger_roundtrip(chars):
    """End-to-end: a plan NAME containing the vulnerable characters flows
    into a chained ledger row via meter._log(); read it back through the
    ledger's real reader (Ledger.__iter__, not a naive .splitlines()) and
    confirm both row count and verify() stay clean."""
    plan_name = "plan_" + "".join(chars) + "_x"
    with tempfile.TemporaryDirectory() as td:
        kp = Path(td) / "keys.json"
        ledger_path = Path(td) / "usage.log.jsonl"
        secret, _ = add_key(kp, plan=plan_name, monthly_cap=5)
        meter = Meter(kp, ledger=ledger_path)
        n_calls = 3
        for _ in range(n_calls):
            r = meter.check(secret)
            assert r and r.ok
        from arcaeon_ledger import Ledger, verify_file
        vr = verify_file(ledger_path)
        assert bool(vr) is True, f"ledger failed to verify: {vr}"
        rows = list(Ledger(ledger_path))
        grant_rows = [row for row in rows if row.get("event") == "meter.grant"]
        assert len(grant_rows) == n_calls, "a grant row was lost/split by the read path"
        assert all(row.get("plan") == plan_name for row in grant_rows), (
            "plan name corrupted across the ledger round-trip")


# ===========================================================================
# 4. Fails-closed: malformed/ambiguous input always denies, never grants
# ===========================================================================

_malformed_keys = st.one_of(
    st.none(),
    st.integers(),
    st.floats(allow_nan=True, allow_infinity=True),
    st.booleans(),
    st.binary(max_size=10),
    st.lists(st.integers(), max_size=3),
    st.dictionaries(st.text(max_size=3), st.integers(), max_size=2),
    st.text(max_size=0),
    st.just("\udce9-lone-surrogate"),
)


@given(bad_key=_malformed_keys)
@_settings
def test_malformed_key_type_always_denies_never_raises_never_grants(bad_key):
    with tempfile.TemporaryDirectory() as td:
        kp = Path(td) / "keys.json"
        add_key(kp, monthly_cap=100)  # a real key exists; bad_key is not it
        meter = Meter(kp)
        result = meter.check(bad_key)  # must never raise
        assert not result
        assert isinstance(result, Denied)
        assert not isinstance(result, Allowance)


# TEST-CONSTRUCTION NOTE (see report): a NaN/Infinity cap written into
# keys.json is a bare `NaN`/`Infinity` literal, which the package REJECTS at
# parse (`keys._reject_constant`) — so it fails closed one stage EARLIER than
# cap-resolution, as `keys_unreadable`, and never reaches `_valid_cap` at all
# through the JSON path. That is still fail-closed (never a grant), just a
# different reason. The three cap regimes below are therefore pinned
# separately so each specific reason is asserted, not loosely OR'd — the
# stress run's initial "failures" were this trap, not a package defect.

# Caps that are valid JSON but not valid caps: caught at cap-resolution.
_resolvable_bad_caps = st.one_of(
    st.floats(allow_nan=False, allow_infinity=False),  # any float: not an int
    st.text(max_size=10),
    st.lists(st.integers(), max_size=3),
    st.integers(max_value=-1),                          # negative
    st.booleans(),                                      # bool is not an int-cap
)


@given(cap=_resolvable_bad_caps)
@_settings
def test_nonint_cap_on_entry_denies_no_cap_configured(cap):
    """A cap that parses as JSON but isn't a valid cap (finite float, str,
    list, negative, bool) sitting directly on the key entry must fail closed
    as `no_cap_configured` — never silently unlimited. This is the
    load-bearing `_valid_cap`/`_resolve_cap` fail-closed path."""
    secret = "am_hyp_fixture_malformed_cap"
    h = key_hash(secret)
    doc = {"version": 1, "keys": {
        h: {"plan": "weird", "monthly_cap": cap, "revoked": False}}}
    with tempfile.TemporaryDirectory() as td:
        kp = Path(td) / "keys.json"
        _write_raw_keys(kp, doc)
        result = Meter(kp).check(secret)
        assert not result and isinstance(result, Denied)
        assert not isinstance(result, Allowance)
        assert result.reason == "no_cap_configured"


@given(cap=st.sampled_from([float("nan"), float("inf"), float("-inf")]))
@_settings
def test_nan_inf_cap_literal_fails_closed_at_parse(cap):
    """A NaN/Infinity cap becomes a bare non-JSON literal in the file; the
    package refuses to parse it (`_reject_constant`), so the WHOLE keys file
    reads as unauthorized — `keys_unreadable`. Still fail-closed (the historic
    NaN-cap-as-silent-unlimited trap can't even round-trip through the
    package's own reader anymore), just caught earlier than cap-resolution."""
    secret = "am_hyp_fixture_nan_cap"
    h = key_hash(secret)
    doc = {"version": 1, "keys": {
        h: {"plan": "weird", "monthly_cap": cap, "revoked": False}}}
    with tempfile.TemporaryDirectory() as td:
        kp = Path(td) / "keys.json"
        _write_raw_keys(kp, doc)
        result = Meter(kp).check(secret)
        assert not result and isinstance(result, Denied)
        assert not isinstance(result, Allowance)
        assert result.reason == "keys_unreadable"


@given(cap=st.one_of(st.sampled_from([float("nan"), float("inf")]),
                    st.floats(allow_nan=False, allow_infinity=False),
                    st.text(max_size=8), st.integers(max_value=-1)))
@_settings
def test_bad_plan_default_cap_denies_no_cap_configured(cap):
    """A bad cap supplied as a plan default via `Meter(plans=...)` (Python
    objects, NOT through JSON — so a NaN float reaches `_valid_cap` directly,
    the one route that still can) must fail closed as `no_cap_configured`,
    never unlimited. The key entry omits its own cap so it genuinely defers to
    the plan default."""
    secret = "am_hyp_fixture_plan_cap"
    h = key_hash(secret)
    doc = {"version": 1, "keys": {h: {"plan": "weird", "revoked": False}}}
    with tempfile.TemporaryDirectory() as td:
        kp = Path(td) / "keys.json"
        _write_raw_keys(kp, doc)
        result = Meter(kp, plans={"weird": cap}).check(secret)
        assert not result and isinstance(result, Denied)
        assert not isinstance(result, Allowance)
        assert result.reason == "no_cap_configured"


# Non-dict entries restricted to JSON-safe values (no NaN/Inf floats, which
# would trip the parse-rejection path tested above instead) so this pins the
# not-a-JSON-object -> unknown_key path specifically.
_malformed_entries = st.one_of(
    st.text(max_size=5), st.integers(),
    st.floats(allow_nan=False, allow_infinity=False),
    st.lists(st.integers(), max_size=3), st.none(), st.booleans(),
)


@given(entry=_malformed_entries)
@_settings
def test_malformed_keys_entry_shape_always_denies(entry):
    """A keys.json entry that parses but isn't a JSON object (corrupted by a
    foreign tool, a bad hand-edit, a partial migration) must deny as
    unknown_key, never crash, never grant."""
    secret = "am_hyp_fixture_bad_entry_shape"
    h = key_hash(secret)
    doc = {"version": 1, "keys": {h: entry}}
    with tempfile.TemporaryDirectory() as td:
        kp = Path(td) / "keys.json"
        _write_raw_keys(kp, doc)
        result = Meter(kp).check(secret)
        assert not result and isinstance(result, Denied)
        assert not isinstance(result, Allowance)
        assert result.reason == "unknown_key"


@given(garbage=st.one_of(
    st.text(max_size=100),
    st.just("{not valid json"),
    st.just("[]"),
    st.just("null"),
    st.just('{"version": 1}'),
    st.just('{"version": 1, "keys": "not-a-dict"}'),
))
@_settings
def test_unreadable_or_malshaped_keys_file_always_denies_never_crashes(garbage):
    with tempfile.TemporaryDirectory() as td:
        kp = Path(td) / "keys.json"
        kp.write_text(garbage, encoding="utf-8")
        meter = Meter(kp)
        result = meter.check("am_" + "x" * 10)  # never raises
        assert not result
        assert isinstance(result, Denied)


@given(cost=st.one_of(
    st.integers(max_value=0), st.floats(), st.text(max_size=5),
    st.booleans(), st.none(),
))
@_settings
def test_invalid_cost_never_grants_silently(cost):
    """`cost` outside "positive int" is documented as a loud ValueError, not
    a silent grant/deny — this pins that it never falls through to an
    Allowance no matter what garbage arrives (a negative cost would be an
    unbounded refund; cost=0 would be free calls at the cap)."""
    with tempfile.TemporaryDirectory() as td:
        kp = Path(td) / "keys.json"
        secret, _ = add_key(kp, monthly_cap=100)
        meter = Meter(kp)
        try:
            result = meter.check(secret, cost=cost)
        except (ValueError, TypeError):
            return  # loud failure — acceptable, this is what's documented
        assert not isinstance(result, Allowance), f"bad cost {cost!r} was silently granted"
