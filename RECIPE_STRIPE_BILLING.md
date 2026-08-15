# Recipe: arcaeon-meter usage export -> Stripe invoice

You meter your agent tool with `arcaeon_meter.Meter`. Month closes. Now you owe
customers invoices that match what they actually used, and — the part every
usage-billing integration eventually has to answer — a way to prove the number
on the invoice isn't just something your server said. This recipe is that path,
end to end, with a working example script.

Companion code: [`examples/stripe_invoice_export.py`](examples/stripe_invoice_export.py).
Run `py examples/stripe_invoice_export.py --selftest` to see it work with zero
setup — synthetic keys, synthetic usage, real `export()` call, real transform,
no Stripe package required.

## The shape of the problem

`meter.export(month="2026-08", fmt="json")` hands you the whole roster for a
billing month — every key, zero-usage keys included, no secrets:

```json
[{"key_id": "159564976fef", "label": "acme-co", "plan": "pro",
  "used": 7, "monthly_cap": null, "revoked": false, "month": "2026-08"}]
```

Turning that into money owed requires three things `arcaeon-meter` deliberately
does NOT do for you (see the package docstring: "Caps are enforcement; payment
is not included"):

1. Map `key_id` (or `label`) to a Stripe `customer` ID — you made that mapping
   when you minted the key; keep it (a JSON file, a row in your own DB,
   whatever you already have).
2. Turn `used` into money: a unit price, a currency, a description.
3. Send it to Stripe *idempotently*, so re-running the export for a month
   already billed never double-charges.

## Which Stripe API: invoice items, not Billing Meters

Stripe has two live paths for usage-based charges:

- **Billing Meters** (`meter_event`, a metered `Price`, attached to a
  running `Subscription`) — built for *streaming* usage into an active
  subscription in near-real-time. It wants a `Meter` object and a metered
  `Price` provisioned ahead of time, and it's designed around the
  subscription's own billing cycle deciding when to invoice.
- **Invoice items** (`stripe.InvoiceItem.create`, `stripe.Invoice.create`) —
  a flat, one-off "bill this customer this amount, now." No `Meter` object,
  no `Price` object, no subscription required.

This recipe uses **invoice items**. `arcaeon-meter`'s own usage store is
already the meter — a monthly batch export from a SQLite counter is the
opposite of streaming, so provisioning Stripe's streaming primitives just to
immediately batch-flatten them back into one number per customer is work with
no payoff. Invoice items also don't force you to pre-create a `Product`/`Price`
per tool: `unit_amount_decimal` + `quantity` on the invoice item computes the
line total directly. Simpler, and it maps 1:1 onto what `export()` already
hands you: one row per key, one line item per row.

If you later want the customer *auto-billed on a rolling subscription cycle*
instead of "I ran a script at month-end," Billing Meters is the right move —
but that's a second integration, not a bigger version of this one.

## The flow

```
meter.export(month, fmt="json")
        |
        v
build_invoice_items(rows, customer_map, unit_amount_cents=...)   <- pure, no network
        |
        v
stripe.InvoiceItem.create(..., idempotency_key=f"arcaeon-meter:{key_id}:{month}")
        |
        v
stripe.Invoice.create(customer=..., pending_invoice_items_behavior="include",
                       auto_advance=True, idempotency_key=f"arcaeon-meter-invoice:{cid}")
```

### 1. Export

```python
from arcaeon_meter import Meter
import json

meter = Meter("keys.json")
rows = json.loads(meter.export(month="2026-08", fmt="json"))
```

### 2. Build the invoice-item payloads (pure — no `stripe` import here)

```python
def build_invoice_items(rows, customer_map, *, unit_amount_cents, currency="usd", month=None):
    items, skipped = [], []
    for row in rows:
        kid, used = row["key_id"], row.get("used", 0)
        billing_month = row.get("month") or month
        if row.get("revoked") or used <= 0:
            skipped.append({"key_id": kid, "reason": "revoked" if row.get("revoked") else "zero_usage"})
            continue
        customer_id = customer_map.get(kid)
        if not customer_id:
            skipped.append({"key_id": kid, "reason": "no_customer_mapping"})
            continue
        items.append({
            "customer": customer_id,
            "currency": currency,
            "quantity": used,
            "unit_amount_decimal": str(unit_amount_cents),
            "description": f"{row.get('label') or kid} - {used} call(s), {billing_month}",
            "idempotency_key": f"arcaeon-meter:{kid}:{billing_month}",
            "metadata": {"arcaeon_meter_key_id": kid, "arcaeon_meter_month": billing_month or ""},
        })
    return items, skipped
```

This is the function you unit-test. It never imports `stripe`, so it never
needs the package installed, an API key, or a network call to verify it's
correct — see "Tested without touching Stripe" below.

### 3. Idempotent send

```python
import stripe, os
stripe.api_key = os.environ["STRIPE_SECRET_KEY"]   # never a literal, never a CLI flag

for it in items:
    kwargs = {k: v for k, v in it.items() if k != "idempotency_key"}
    stripe.InvoiceItem.create(**kwargs, idempotency_key=it["idempotency_key"])
```

`idempotency_key` is keyed on `(key_id, month)` — the natural primary key of a
billing run. Re-run the whole export for a month you already billed (cron
retried, you re-ran it by hand to double-check a number) and Stripe returns
the *original* invoice item for each key instead of creating a duplicate. You
don't track "did I already bill this" state yourself; Stripe's idempotency
layer already does, and the key you hand it *is* that state, derived, not
stored.

### 4. Finalize one invoice per customer

```python
stripe.Invoice.create(
    customer=customer_id,
    pending_invoice_items_behavior="include",  # standalone invoices default to EXCLUDE
    auto_advance=True,
    idempotency_key=f"arcaeon-meter-invoice:{customer_id}",
)
```

`pending_invoice_items_behavior` has to be explicit — Stripe's default for a
standalone (non-subscription) invoice is to create an *empty* draft and leave
your pending items uncollected. `auto_advance=True` lets Stripe finalize and
attempt collection on its own schedule instead of you calling
`finalize_invoice` by hand.

## Testing this without a Stripe account, a key, or a network call

`build_invoice_items()` is a pure function over data `arcaeon-meter` already
gives you — it never imports `stripe`. `examples/stripe_invoice_export.py`
puts the network calls (`send_invoice_items`, `create_and_finalize_invoices`)
behind a local `import stripe` that only executes with `--live`. Everything
else — `--selftest`, `--dry-run` — never imports the package and never needs
`STRIPE_SECRET_KEY` set.

Real run, real output (`py examples/stripe_invoice_export.py --selftest`):

```
meter.export() rows:
[
  {
    "key_id": "159564976fef",
    "label": "acme-co",
    "plan": "pro",
    "used": 7,
    "monthly_cap": null,
    "revoked": false,
    "month": "2026-08"
  },
  {
    "key_id": "4d9a31a7daed",
    "label": "never-called",
    "plan": "free",
    "used": 0,
    "monthly_cap": 100,
    "revoked": false,
    "month": "2026-08"
  },
  {
    "key_id": "e5a6731f9f63",
    "label": "beta-user",
    "plan": "free",
    "used": 3,
    "monthly_cap": 100,
    "revoked": false,
    "month": "2026-08"
  }
]

build_invoice_items() ->
2 invoice item(s) to create, 1 key(s) skipped

  + customer=cus_test_acme qty=7 unit_amount_decimal=5 idempotency_key=arcaeon-meter:159564976fef:2026-08
    description: acme-co - 7 call(s), plan pro, 2026-08
  + customer=cus_test_beta qty=3 unit_amount_decimal=5 idempotency_key=arcaeon-meter:e5a6731f9f63:2026-08
    description: beta-user - 3 call(s), plan free, 2026-08
  - skip key_id=4d9a31a7daed reason=zero_usage used=0

PASS: 2 billable items, 1 skipped (zero_usage), idempotency keys stable across re-run
```

The self-test also proves the idempotency claim directly: it calls
`build_invoice_items()` twice against the same export and asserts the
`idempotency_key` set is identical both times — the property the whole
double-billing defense rests on, checked in code, not asserted in prose.

When you're ready to test the network half, use Stripe's own test-mode
patterns — a `sk_test_...` key (never `sk_live_...`) in `STRIPE_SECRET_KEY`,
and Stripe's [documented test card numbers](https://docs.stripe.com/testing)
if you carry the invoice through to payment. No real Stripe call is made
anywhere in this recipe's own tests; `--live` is the only code path that
touches the network, and it's opt-in per run.

## The honesty angle: the ledger makes the invoice disputable, not just billable

`used: 7` on the export is a claim. By default it's a SQLite counter — real,
but if a customer says "I was only charged for calls I actually made, prove
it," your answer is "trust my database." Wire the ledger and the answer
changes shape:

```python
meter = Meter("keys.json", ledger="usage_ledger.jsonl")
```

Every grant *and* denial now appends a hash-chained row via `arcaeon-ledger`
— not a copy of the count, the actual events that produced it:

```
{"event": "meter.grant", "key_id": "178e09b09ead", "plan": "pro", "month": "2026-08", "used": 1, "cost": 1, "ts": "2026-08-15T01:04:12Z", "chain": "24b93e7ffb68834ee10121d43cc1b9f6"}
{"event": "meter.grant", "key_id": "178e09b09ead", "plan": "pro", "month": "2026-08", "used": 2, "cost": 1, "ts": "2026-08-15T01:04:12Z", "chain": "2412996c9472c27766405977156f2e6c"}
...
{"event": "meter.grant", "key_id": "178e09b09ead", "plan": "pro", "month": "2026-08", "used": 7, "cost": 1, "ts": "2026-08-15T01:04:12Z", "chain": "a110d92c0795f2d96262fb39ceeee502"}
```

A bill dispute stops being "let me re-check my database" and becomes a
`verify()` call:

```python
import arcaeon_ledger as al
result = al.Ledger("usage_ledger.jsonl").verify()
# VerifyResult(ok=True, rows=7, chained=7, prechain=0, first_break=None)
```

`ok=True` means every row's hash chains to the one before it — nobody edited,
reordered, or deleted a grant event after the fact without breaking the chain
at that exact row (`first_break` names it if so). `rows=7` matching the
invoice's `quantity=7` is the receipt: the number on the Stripe invoice is the
count of individually-chained, individually-timestamped grant events, not a
number that could have been typed in or silently adjusted. That's the sell —
not "trust our metering," but "here's the chain, verify it yourself."

Two honest limits, stated plainly so this doesn't oversell: `verify()` proves
the ledger wasn't tampered with *after* being written — it doesn't prove your
code called `meter.check()` on every real usage event in the first place (the
gateway-completeness problem the package docstring already names). And the
ledger is optional (`Meter(..., ledger=...)`, soft dep on `arcaeon-ledger`) —
if you skip it, you're back to "trust the SQLite count," which is still
accurate, just not independently checkable after the fact.

## Where the secret key goes

`STRIPE_SECRET_KEY` — an environment variable, read once at the call site
(`os.environ[STRIPE_SECRET_KEY]`), never a CLI argument (shell history, `ps`
output), never a literal in source or in `keys.json`/`customers.json`. Test
mode vs. live mode is entirely which key you export — `sk_test_...` for
everything in this recipe until you've watched a real test-mode invoice go
through the Dashboard.

## Docs-only note

This recipe and its example script don't change `arcaeon_meter`'s code, so
the package version stays at `0.1.0` — this rides the repo, not the wheel. If
a future recipe needs a code change (e.g., a helper baked into the package),
that's a real version bump with its own CHANGELOG entry; this one isn't that.
