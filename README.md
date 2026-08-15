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

Export columns: `key_id, label, plan, used, monthly_cap, revoked, month` — every key
appears, zero-usage rows included, secrets never. The Stripe recipe is deliberately a
how-to, not code: at month close, `export(month="2026-08", fmt="csv")`, then for each
row create an invoice item (`used × your unit price`, or a flat plan price with
`used` as the line description) against the customer you mapped to `label`/`key_id`
when you minted the key. That's the whole integration; this library stays out of the
money path on purpose.

## HTTP in one line

```python
app.add_middleware(meter.asgi_middleware())   # FastAPI / Starlette / any ASGI
```

Checks `Authorization: Bearer <key>`, answers `401` (missing/unknown/revoked) or
`429` (over cap, with `X-Meter-Cap` / `X-Meter-Used` headers) with a JSON reason,
and stashes the `Allowance` at `scope["arcaeon_meter"]` for your handlers. It speaks
raw ASGI — no framework import, nothing extra to install.

## Metering you can audit (optional)

```python
meter = Meter("keys.json", ledger="usage.log.jsonl")   # pip install arcaeon-meter[ledger]
```

Every grant **and** denial appends a hash-chained row via
[arcaeon-ledger](https://pypi.org/project/arcaeon-ledger/), so the usage record you
bill from is tamper-evident: edit a row mid-history and `verify()` names the exact
line. When a customer disputes an invoice, you have a chained record, not a mutable
counter. Soft dependency — only needed if you pass `ledger=`.

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

Also: only HTTP scopes are metered by the ASGI middleware. WebSocket
connections are refused rather than waved through — if you need WS traffic
metered, meter the handshake yourself.

MIT. Built by [Arcaeon](https://arcaeon.io) — the evidence layer for AI.
