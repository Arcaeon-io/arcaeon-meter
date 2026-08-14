# Changelog — arcaeon-meter

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
