# Changelog — arcaeon-meter

## 0.1.1 — 2026-08-14

Hostile audit of the fail-closed claim. It did not hold on five paths; it does
now. Every fix is in the deny direction, so nothing that was legitimately
granted before is denied today.

- **A cap that isn't a cap is no longer unlimited.** `used + cost > cap` is
  `False` for both `NaN` and `+Infinity`, so either one in a keys file was a
  silent unlimited grant — and `json.loads` accepts the bare `NaN`/`Infinity`
  literals, so it round-tripped through this package's own writer. Caps are
  now validated as `None` (explicit unlimited) or a non-negative `int`;
  anything else resolves to `no_cap_configured`. `keys.load()` also rejects
  the non-JSON literals at parse time, and `keys.save()` refuses to write
  them.
- **`cost=` must be a positive int.** It is a public kwarg and the SQL is
  `used = used + ?`, so a negative cost was an unbounded refund that persisted
  in SQLite across processes, and `cost=0` was unlimited free calls at the cap.
  Both now raise `ValueError` before anything is read or written.
- **Malformed keys and unreadable keys files are typed denials.** A lone
  surrogate (`"am_\ud800"`) is legal JSON, so it arrives from the wire; it used
  to escape `except MeterDenied` as a `UnicodeEncodeError` and 500 instead of
  401. New reasons: `malformed_key`, `keys_unreadable`. A corrupt or truncated
  keys file now denies rather than raising out of `json`.
- **The ASGI middleware no longer waves through non-HTTP scopes.** WebSocket
  connections bypassed metering entirely — unkeyed, uncapped, on the exact
  protocol where unbounded work hides. `lifespan` still passes through; a
  websocket scope is closed with 1008.
- **Revocation survives a concurrent write.** `add_key`/`revoke_key` were
  load-mutate-save with no lock, so a concurrent add rewrote the document from
  a stale read and silently un-revoked a key the CLI had just reported as
  revoked. The whole cycle now runs under a cross-process lock; `save()` fsyncs
  and retries `os.replace` (on Windows it fails with `PermissionError` while a
  reader holds the file, which made "revocation takes effect without a restart"
  false in practice).
- **A failed ledger write rolls the count back.** The grant was chained *after*
  the commit, so a ledger failure billed for a call that raised before it ran,
  and `verify()` reported `ok` across the gap (a missing row is not an altered
  one). The chain write now happens inside the transaction.
- **Key-id prefixes shorter than 6 chars are refused.** `revoke_key(kp, "")`
  resolved to whichever key sorted first — an unset `$KEY_ID` in an ops script
  could revoke a key at random. Same guard on `usage()`.
- Keys-file cache invalidation now keys on size + inode + ctime as well as
  mtime, so a coarse-granularity filesystem or a timestamp-preserving copy
  can't leave a revoked key spending until restart.

Known, not fixed in this release (documented rather than papered over): if the
usage SQLite file is deleted or not persisted, every budget resets to zero on
the next start. See the README honesty section.

## 0.1.0 — 2026-08-14

Initial release. Keyed usage metering for agent tools, stdlib-only.

- `Meter("keys.json")` + `@meter.metered` decorator (the 3-line promise) and
  `meter.check(key)` returning truth-testable `Allowance | Denied`; denials are
  typed (`over_cap`, `revoked`, `unknown_key`, `missing_key`,
  `no_cap_configured`) — never a silent pass, and an unresolvable cap fails
  CLOSED rather than defaulting to unlimited.
- SQLite (WAL) usage counts per key per UTC month; check-then-increment inside
  a `BEGIN IMMEDIATE` transaction — proven by a two-process contention test
  (400 competing attempts vs cap=300 grants exactly 300).
- Key management CLI (`python -m arcaeon_meter keys add|revoke|list`, plus
  `usage` and `export`): random `am_` secrets shown once, stored sha256-hashed
  only; revocation is live (keys file re-read on mtime change).
- Billing handoff: `usage(key_or_id)` and `export(fmt="json"|"csv")` — full
  roster, invoice-ready, no secrets; Stripe recipe documented as a how-to
  (no payment code by design).
- Optional pure-ASGI middleware (`meter.asgi_middleware()`) — bearer-key
  checks for FastAPI/Starlette/any ASGI with 401/429 JSON denials; zero
  framework imports.
- Optional tamper-evident record: `Meter(..., ledger="usage.log.jsonl")`
  hash-chains every grant/denial via arcaeon-ledger (soft dep,
  `pip install arcaeon-meter[ledger]`; missing dep is a loud ImportError).
- Why keyed (not x402) for v0.1: per Arcaeon research #26 (2026-08-14),
  keyed API + Stripe is the revenue rail for the next 12 months; x402 demand
  is still mostly self-dealing. An x402 adapter remains a later shop-window
  add-on, out of scope here.
