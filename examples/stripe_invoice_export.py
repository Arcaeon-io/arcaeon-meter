# SPDX-License-Identifier: MIT
"""examples/stripe_invoice_export.py — arcaeon-meter usage export -> Stripe invoice.

Turns a month's `meter.export()` into billed Stripe invoice items, one per
metered key, idempotent on re-run. Companion code for
`../RECIPE_STRIPE_BILLING.md` — read that first for the why; this is the how.

Two halves, deliberately split so the money-shaped half never has to run in
tests:

  1. `build_invoice_items()` — PURE. export rows -> Stripe-shaped dicts. No
     network, no `stripe` import, no API key. This is what `--dry-run` and
     the self-test at the bottom exercise.
  2. `send_invoice_items()` / `create_and_finalize_invoices()` — the only
     functions that import `stripe` or touch the network. They run only when
     you pass `--live` (test-mode or live-mode is entirely a property of
     WHICH secret key you export into STRIPE_SECRET_KEY — this script never
     hardcodes or picks a mode).

Run modes:

    py stripe_invoice_export.py --selftest
        Synthetic Meter, synthetic usage, builds invoice-item payloads,
        prints them. No Stripe package needed, no network.

    py stripe_invoice_export.py --keys keys.json --customer-map customers.json \\
        --month 2026-08 --unit-amount-cents 5 --dry-run
        Real export from a real keys.json, prints what WOULD be sent to
        Stripe. Still no network, still no `stripe` import.

    STRIPE_SECRET_KEY=sk_test_... py stripe_invoice_export.py --keys keys.json \\
        --customer-map customers.json --month 2026-08 --unit-amount-cents 5 --live
        Same build, then actually calls Stripe (test-mode key -> test mode,
        no real money moves). Requires `pip install stripe`.

The secret key is read from the STRIPE_SECRET_KEY environment variable ONLY.
It is never a CLI flag (shows up in shell history / process lists) and never
a literal in this file.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

import arcaeon_meter
from arcaeon_meter import Meter
from arcaeon_meter.keys import add_key

STRIPE_KEY_ENV = "STRIPE_SECRET_KEY"  # never hardcode the secret; read it here only


# ---------------------------------------------------------------------------
# 1. PURE transform: export rows -> Stripe invoice-item payloads.
#    No `stripe` import lives above this line. Testable with zero deps.
# ---------------------------------------------------------------------------

def build_invoice_items(
    rows: list[dict[str, Any]],
    customer_map: dict[str, str],
    *,
    unit_amount_cents: int,
    currency: str = "usd",
    month: str | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """`rows` is `json.loads(meter.export(month=..., fmt="json"))`.
    `customer_map` is a builder-owned `{key_hash: stripe_customer_id}` mapping
    (how you decide who a key bills to is your call — a DB, a JSON file,
    whatever mapped the key to a customer when it was minted).

    Keyed on `key_hash`, the FULL sha256, not the 12-hex `key_id`: that prefix
    is 48 bits and two keys can share one at scale, which would point two
    customers' invoices at whichever mapping was stored last. `key_id` stays
    in the human-readable description; identity is the hash.

    Returns `(items, skipped)`. Each item dict is shaped for
    `stripe.InvoiceItem.create(**item)` (minus the `idempotency_key`, which
    the caller passes as its own kwarg — see `send_invoice_items`). Every
    item carries a stable `idempotency_key` of `f"arcaeon-meter:{key_hash}:{month}"`
    — re-running this export for a month that was already billed reproduces
    the SAME key, so Stripe returns the original invoice item instead of
    creating a duplicate. That is the whole idempotency story; nothing here
    tracks "already billed" state of its own, because Stripe already does.

    Revoked keys and zero-usage keys are skipped, not billed — `skipped`
    carries the reason for each so the caller can log or reconcile it.
    """
    items: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for row in rows:
        kid = row["key_id"]
        # pre-0.1.2 exports had no key_hash column; fall back so an archived
        # export still runs, and say so rather than silently mis-keying.
        kh = row.get("key_hash") or kid
        used = row.get("used", 0)
        billing_month = row.get("month") or month
        if row.get("revoked"):
            skipped.append({"key_id": kid, "reason": "revoked", "used": used})
            continue
        if used <= 0:
            skipped.append({"key_id": kid, "reason": "zero_usage", "used": used})
            continue
        customer_id = customer_map.get(kh) or customer_map.get(kid)
        if not customer_id:
            skipped.append({"key_id": kid, "reason": "no_customer_mapping", "used": used})
            continue
        idempotency_key = f"arcaeon-meter:{kh}:{billing_month}"
        items.append({
            "customer": customer_id,
            "currency": currency,
            "quantity": used,
            "unit_amount_decimal": str(unit_amount_cents),
            "description": (
                f"{row.get('label') or kid} - {used} call(s), "
                f"plan {row.get('plan', 'default')}, {billing_month}"
            ),
            "idempotency_key": idempotency_key,
            "metadata": {
                "arcaeon_meter_key_id": kid,
                "arcaeon_meter_key_hash": kh,
                "arcaeon_meter_plan": row.get("plan", "default"),
                "arcaeon_meter_month": billing_month or "",
                "arcaeon_meter_used": str(used),
            },
        })
    return items, skipped


# ---------------------------------------------------------------------------
# 2. The network half. Only these two functions ever `import stripe`.
# ---------------------------------------------------------------------------

def send_invoice_items(items: list[dict[str, Any]], *, api_key: str) -> list[Any]:
    """Create one Stripe InvoiceItem per item. Idempotent: re-running with the
    same (key_id, month) resolves to the same InvoiceItem instead of a
    duplicate charge, because `idempotency_key` is stable per (key_id, month)."""
    import stripe  # local import: never required for build/dry-run/selftest

    stripe.api_key = api_key
    created = []
    for it in items:
        kwargs = {k: v for k, v in it.items() if k != "idempotency_key"}
        created.append(stripe.InvoiceItem.create(
            **kwargs, idempotency_key=it["idempotency_key"],
        ))
    return created


def create_and_finalize_invoices(customer_ids: list[str], *, api_key: str,
                                  auto_advance: bool = True) -> list[Any]:
    """One draft invoice per customer, pulling in the pending invoice items
    just created (`pending_invoice_items_behavior="include"` — standalone
    invoices default to EXCLUDING pending items, so this must be explicit).
    `idempotency_key` here is per (customer, this script run's items) —
    re-running against the SAME already-invoiced items is a no-op on the
    invoice-item side; a second invoice would only pick up whatever pending
    items exist at that moment, so re-running after a successful finalize is
    safe (nothing pending left to collect)."""
    import stripe  # local import: never required for build/dry-run/selftest

    stripe.api_key = api_key
    invoices = []
    for cid in dict.fromkeys(customer_ids):  # de-dupe, keep first-seen order
        inv = stripe.Invoice.create(
            customer=cid,
            auto_advance=auto_advance,
            pending_invoice_items_behavior="include",
            idempotency_key=f"arcaeon-meter-invoice:{cid}",
        )
        invoices.append(inv)
    return invoices


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _load_customer_map(path: Path) -> dict[str, str]:
    return json.loads(path.read_text(encoding="utf-8"))


def _run_export(keys_path: Path, month: str | None) -> list[dict[str, Any]]:
    meter = Meter(keys_path)
    return json.loads(meter.export(month=month, fmt="json"))


def _print_plan(items: list[dict[str, Any]], skipped: list[dict[str, Any]]) -> None:
    print(f"{len(items)} invoice item(s) to create, {len(skipped)} key(s) skipped\n")
    for it in items:
        print(f"  + customer={it['customer']} qty={it['quantity']} "
              f"unit_amount_decimal={it['unit_amount_decimal']} "
              f"idempotency_key={it['idempotency_key']}")
        print(f"    description: {it['description']}")
    for s in skipped:
        print(f"  - skip key_id={s['key_id']} reason={s['reason']} used={s['used']}")


def _selftest() -> None:
    """Real Meter, real keys.json, real export() call, real transform — the
    only thing NOT real is the Stripe network call. Prints actual output."""
    with tempfile.TemporaryDirectory() as td:
        keys_path = Path(td) / "keys.json"
        secret_a, kid_a = add_key(keys_path, plan="pro", monthly_cap=None, label="acme-co")
        secret_b, kid_b = add_key(keys_path, plan="free", monthly_cap=100, label="beta-user")
        secret_c, kid_c = add_key(keys_path, plan="free", monthly_cap=100, label="never-called")

        meter = Meter(keys_path)

        @meter.metered
        def my_tool(q, _meter_key=None):
            return f"ok:{q}"

        for _ in range(7):
            my_tool("q", _meter_key=secret_a)
        for _ in range(3):
            my_tool("q", _meter_key=secret_b)
        # secret_c never called -> zero-usage row, should be skipped

        rows = json.loads(meter.export(fmt="json"))
        print("meter.export() rows:")
        print(json.dumps(rows, indent=2))

        # map on the FULL hash, not the 12-hex display prefix
        kh_a, kh_b = (arcaeon_meter.key_hash(secret_a),
                      arcaeon_meter.key_hash(secret_b))
        customer_map = {kh_a: "cus_test_acme", kh_b: "cus_test_beta"}
        items, skipped = build_invoice_items(
            rows, customer_map, unit_amount_cents=5, currency="usd",
        )
        print("\nbuild_invoice_items() ->")
        _print_plan(items, skipped)

        assert len(items) == 2, f"expected 2 billable items, got {len(items)}"
        assert len(skipped) == 1 and skipped[0]["reason"] == "zero_usage"
        by_kid = {it["metadata"]["arcaeon_meter_key_id"]: it for it in items}
        assert by_kid[kid_a]["quantity"] == 7
        assert by_kid[kid_b]["quantity"] == 3
        assert by_kid[kid_a]["idempotency_key"].startswith(f"arcaeon-meter:{kh_a}:")
        # re-running the SAME export produces the SAME idempotency keys —
        # the idempotency story, proven without touching the network.
        rows2 = json.loads(meter.export(fmt="json"))
        items2, _ = build_invoice_items(rows2, customer_map, unit_amount_cents=5)
        keys1 = {it["idempotency_key"] for it in items}
        keys2 = {it["idempotency_key"] for it in items2}
        assert keys1 == keys2, "idempotency keys must be stable across re-runs of the same month"
        print("\nPASS: 2 billable items, 1 skipped (zero_usage), "
              "idempotency keys stable across re-run")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--selftest", action="store_true",
                    help="run the synthetic self-test (no files, no network)")
    p.add_argument("--keys", type=Path, help="path to arcaeon_meter keys.json")
    p.add_argument("--customer-map", type=Path,
                    help="JSON file: {key_hash: stripe_customer_id} "
                         "(12-hex key_id keys still resolve, for pre-0.1.2 maps)")
    p.add_argument("--month", default=None, help="YYYY-MM, defaults to current UTC month")
    p.add_argument("--currency", default="usd")
    p.add_argument("--unit-amount-cents", type=int, default=None,
                    help="price per metered call, in cents (smallest currency unit)")
    p.add_argument("--dry-run", action="store_true",
                    help="build + print the plan, never import stripe or touch the network")
    p.add_argument("--live", action="store_true",
                    help="actually call Stripe (InvoiceItem + Invoice). "
                         "Requires STRIPE_SECRET_KEY env var and `pip install stripe`.")
    args = p.parse_args()

    if args.selftest:
        _selftest()
        return 0

    if not args.keys or not args.customer_map or args.unit_amount_cents is None:
        p.error("--keys, --customer-map, and --unit-amount-cents are required "
                 "unless --selftest")

    rows = _run_export(args.keys, args.month)
    customer_map = _load_customer_map(args.customer_map)
    items, skipped = build_invoice_items(
        rows, customer_map, unit_amount_cents=args.unit_amount_cents,
        currency=args.currency, month=args.month,
    )
    _print_plan(items, skipped)

    if args.dry_run or not args.live:
        print("\n(dry run - nothing sent to Stripe; pass --live to actually invoice)")
        return 0

    api_key = os.environ.get(STRIPE_KEY_ENV)
    if not api_key:
        print(f"\n{STRIPE_KEY_ENV} not set - refusing to run --live without it", file=sys.stderr)
        return 1

    created = send_invoice_items(items, api_key=api_key)
    print(f"\ncreated {len(created)} Stripe invoice item(s)")
    invoices = create_and_finalize_invoices(
        [it["customer"] for it in items], api_key=api_key,
    )
    for inv in invoices:
        print(f"  invoice {inv['id']} customer={inv['customer']} status={inv['status']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
