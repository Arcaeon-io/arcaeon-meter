# arcaeon-meter

**Meter your agent tool in 3 lines: keys, monthly caps, usage you can bill from.**
*Pure stdlib. SQLite counts. Keys hashed at rest. No billing infrastructure required.*

```bash
pip install arcaeon-meter
```

## Why

You shipped a tool agents actually call. Day two you need what every API business
needs on day one: per-customer keys, a free tier with a real cap, and a usage record
you can invoice from. The usual answer is a gateway product, a billing platform, and
an afternoon of webhooks — heavy for a tool that charges cents.

`arcaeon-meter` is the small version: a keys file, a SQLite counter, and a decorator.
Caps are **enforced** (a denial is a typed exception, never a silent pass), counts
survive concurrent processes, and `export()` hands your billing flow exactly what an
invoice run wants.

## Use

```python
from arcaeon_meter import Meter
meter = Meter("keys.json")

@meter.metered
def my_tool(query, _meter_key=None): ...
```

Callers pass their key as `_meter_key`. Every call is checked against the keys file
and counted against the key's monthly cap. Denials raise `MeterDenied` with a
machine-readable reason (`over_cap`, `revoked`, `unknown_key`, `missing_key`) —
catch it and answer however your surface answers.

Prefer explicit control? Same check, no exception:

```python
result = meter.check(key)          # -> Allowance | Denied, both truth-testable
if result:
    ...                            # result.used, result.cap, result.remaining
else:
    ...                            # result.reason == "over_cap", result.used, ...
```

`meter.check(key, record=False)` peeks (validates + reports usage) without counting.

## Keys

```bash
python -m arcaeon_meter keys add --plan free --cap 100 --label alice
# key_id: 3f9a1c2b7d40
# secret: am_Vq...   <- shown ONCE, never stored

python -m arcaeon_meter keys list
python -m arcaeon_meter keys revoke 3f9a1c2b7d40
```

Secrets are random (~192 bits) and stored **only as sha256 hashes** — leaking
`keys.json` does not leak keys. Revocation marks the entry (kept for audit) and takes
effect in a running server without a restart (the file is re-read on change). Caps
can live per key (`--cap`, `--unlimited`) or per plan (`Meter(plans={"free": 100})`);
a key with no resolvable cap is **denied, not unlimited** — the meter fails closed.

## Billing handoff

```python
meter.usage(key_or_id)         # one key: used / cap / remaining this month
meter.export(fmt="csv")        # whole roster for the month, invoice-ready
```

Export columns: `key_id, key_hash, label, plan, used, monthly_cap, revoked, month` —
every key appears, zero-usage rows included, secrets never. The Stripe recipe is
deliberately a how-to, not code: at month close, `export(month="2026-08", fmt="csv")`,
then for each row create an invoice item (`used × your unit price`, or a flat plan
price with `used` as the line description) against the customer you mapped when you
minted the key. That's the whole integration; this library stays out of the money path
on purpose.

**Map customers on `key_hash`, not `key_id`.** `key_id` is a 12-hex display prefix —
48 bits, so two keys can share one (see the honesty section). `key_hash` is the full
sha256 that counts are keyed on: unambiguous, stable, and the same one-way hash already
sitting in `keys.json`. It is not a secret and cannot be reversed to one; plaintext
secrets still appear nowhere.

## HTTP in one line

```python
app.add_middleware(meter.asgi_middleware())   # FastAPI / Starlette / any ASGI
```

Checks `Authorization: Bearer <key>`, answers `401` (missing/unknown/revoked) or
`429` (over cap, with `X-Meter-Cap` / `X-Meter-Used` headers) with a JSON reason,
and stashes the `Allowance` at `scope["arcaeon_meter"]` for your handlers. It speaks
raw ASGI — no framework import, nothing extra to install.

**What it bills, stated plainly** (since 0.1.2): `OPTIONS` is **not** metered — a CORS
preflight is the browser asking whether it may call, and it carries no `Authorization`
header, so metering it billed a non-call *and* answered 401, breaking the handshake it
was inspecting. Every other method **including `HEAD`** is billed once at dispatch;
pass `meter.asgi_middleware(skip_methods=("OPTIONS", "HEAD"))` if a HEAD isn't a call
to you. A request your handler answers **5xx is still billed** — the cap has to be spent
*before* the work runs (that's what makes it a cap, and what makes it atomic across
processes), and refunding would need a negative cost, which is refused by design.
Credit failed calls in your billing flow, where the money actually is.

## Metering you can audit (optional)

```python
meter = Meter("keys.json", ledger="usage.log.jsonl")   # pip install arcaeon-meter[ledger]
```

Every grant **and** denial appends a hash-chained row via
[arcaeon-ledger](https://pypi.org/project/arcaeon-ledger/), so the usage record you
bill from is tamper-evident: edit a row mid-history and `verify()` names the exact
line. When a customer disputes an invoice, you have a chained record, not a mutable
counter. Soft dependency — only needed if you pass `ledger=`.

**The invariant is `grants − voids == the billed count`, not `grants == count`.** The
ledger and SQLite are two stores and cannot be made atomic cheaply. The grant is
chained *inside* the transaction, so a failed ledger write rolls the count back (nobody
is billed for a call that raised). The reverse — ledger written, then `COMMIT` fails
(disk full, I/O error) — leaves a chained row SQLite never accepted, and it can't be
deleted without breaking the chain. So its inverse is chained instead: a `meter.void`
row carrying `reason: "commit_failed"`. Net the two when you reconcile. If the void
append *also* fails (the disk that just failed you, failing again), the ledger stays
`+cost` ahead of the count — which the same netting exposes, and your caller sees the
raised error. That's the whole seam, disclosed.

## Concurrency

Counts live in SQLite (WAL mode); check-then-increment runs inside an `IMMEDIATE`
transaction, so parallel workers neither lose counts nor double-grant the last slot
under a cap. The test suite proves both with two real OS processes contending on one
database.

## What it enforces / what it doesn't

**Enforces:** key validity, revocation, and monthly caps — on every call that goes
through the meter.

**Doesn't:** an in-process wrapper meters what the meter *saw*. Code that calls your
inner function directly bypasses it — the voluntary-path problem, and no library-level
wrapper escapes it. Narrow it by metering at your real boundary (the ASGI middleware,
if HTTP is your edge). And **payment is not included**: caps stop over-use, but money
moves in *your* billing flow — this library feeds it and stays out of it. If you need
crypto-native machine payments (x402 et al.), that's a different rail; keyed metering
is the one that bills today.

**And the one that will bite you: the usage DB is state, so treat it like state.**
Counts live in SQLite next to the keys file. Delete it, forget to mount the
volume, `git clean` it, rebuild the container without a persistent path — and
every exhausted budget is full again, silently, because an empty counts table
is indistinguishable from a fresh install. Put the DB on a persistent volume,
back it up with the keys file, and if you want a second copy that can't be lost
this way, run with `ledger=` — every grant is a chained row you can re-total.
Metering is only as durable as the thing counting.

**Fixed in 0.1.2, disclosed because it shipped: through 0.1.1 the usage table was
keyed on the 12-hex `key_id`.** That is 48 bits. Two customers whose key hashes shared
those 12 hex shared one billing row — the busy one's calls invoiced to *both*, and the
quiet one's cap polluted by traffic it never sent. Birthday odds put that at ~50%
around **16.7M keys**, which is inside this product's own "millions of agents" pitch,
not a theoretical footnote. From 0.1.2 counts key on the **full sha256**; `key_id` is
display only. Opening an older database migrates it: rows whose prefix matches exactly
one key in your keys file carry over intact (the roster is the whole universe of keys
that could have incremented them), and rows that matched two keys — the merged rows,
the defect itself — **cannot be split by anyone**, because truncation isn't reversible.
Those are preserved as `legacy_truncated_keyspace:<prefix>`, kept out of `export()`
(nobody can be honestly invoiced for a count with an unknown owner), and readable via
`meter.legacy_usage()`; `export` on the CLI warns when any exist. Your original table
is kept as `usage_pre_0_1_2`. If the keys file can't be read, the migration refuses to
run rather than zero out every recoverable count.

Also: only HTTP scopes are metered by the ASGI middleware. WebSocket
connections are refused rather than waved through — if you need WS traffic
metered, meter the handshake yourself.

MIT. Built by [Arcaeon](https://arcaeon.io) — the evidence layer for AI.
