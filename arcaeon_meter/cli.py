# SPDX-License-Identifier: MIT
"""CLI for arcaeon_meter.

    python -m arcaeon_meter keys add    [--keys keys.json] [--plan free]
                                        [--cap 100 | --unlimited] [--label X]
    python -m arcaeon_meter keys revoke <key_id-or-secret> [--keys ...]
    python -m arcaeon_meter keys list   [--keys ...]
    python -m arcaeon_meter usage <key_id-or-secret> [--keys ...] [--db ...]
    python -m arcaeon_meter export      [--month YYYY-MM] [--fmt json|csv]

`keys add` prints the secret ONCE — it is never stored, only its hash.
"""
from __future__ import annotations

import argparse
import sys

from arcaeon_meter import Meter, __version__
from arcaeon_meter import keys as keymod


def _add_keys_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument("--keys", default="keys.json",
                   help="keys file path (default: keys.json)")


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        prog="arcaeon-meter",
        description="Keyed usage metering for agent tools: keys, monthly "
                    "caps, SQLite counts, billing export.")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    pk = sub.add_parser("keys", help="manage API keys (hashed at rest)")
    ksub = pk.add_subparsers(dest="kcmd", required=True)

    pa = ksub.add_parser("add", help="mint a key; prints the secret ONCE")
    _add_keys_arg(pa)
    pa.add_argument("--plan", default="free")
    capg = pa.add_mutually_exclusive_group()
    capg.add_argument("--cap", type=int, default=100,
                      help="monthly cap (default: 100)")
    capg.add_argument("--unlimited", action="store_true",
                      help="explicitly no cap")
    pa.add_argument("--label", default=None, help="human name for exports")

    pr = ksub.add_parser("revoke", help="revoke by key_id or secret")
    _add_keys_arg(pr)
    pr.add_argument("ident")

    pl = ksub.add_parser("list", help="list keys (ids only, never secrets)")
    _add_keys_arg(pl)

    pu = sub.add_parser("usage", help="one key's usage this month")
    _add_keys_arg(pu)
    pu.add_argument("ident", help="key_id or secret")
    pu.add_argument("--db", default=None)
    pu.add_argument("--month", default=None)

    pe = sub.add_parser("export", help="whole-roster usage for billing")
    _add_keys_arg(pe)
    pe.add_argument("--db", default=None)
    pe.add_argument("--month", default=None)
    pe.add_argument("--fmt", choices=["json", "csv"], default="json")

    args = ap.parse_args(argv)

    if args.cmd == "keys":
        if args.kcmd == "add":
            cap = None if args.unlimited else args.cap
            secret, kid = keymod.add_key(args.keys, plan=args.plan,
                                         monthly_cap=cap, label=args.label)
            print(f"key_id: {kid}")
            print(f"secret: {secret}")
            print("Store the secret now — it is not saved anywhere "
                  "(only its hash is).")
            return 0
        if args.kcmd == "revoke":
            try:
                kid = keymod.revoke_key(args.keys, args.ident)
            except KeyError as e:
                print(f"error: {e}", file=sys.stderr)
                return 1
            print(f"revoked: {kid}")
            return 0
        if args.kcmd == "list":
            rows = keymod.list_keys(args.keys)
            if not rows:
                print("(no keys)")
                return 0
            for r in rows:
                cap = r.get("monthly_cap", "(plan default)")
                cap = "unlimited" if cap is None else cap
                flag = "  REVOKED" if r.get("revoked") else ""
                label = f"  label={r['label']}" if r.get("label") else ""
                print(f"{r['key_id']}  plan={r.get('plan', 'default')}  "
                      f"cap={cap}{label}{flag}")
            return 0

    if args.cmd == "usage":
        meter = Meter(args.keys, db=args.db)
        try:
            u = meter.usage(args.ident, month=args.month)
        except KeyError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        cap = "unlimited" if u.cap is None else u.cap
        rem = "" if u.remaining is None else f"  remaining={u.remaining}"
        rev = "  REVOKED" if u.revoked else ""
        print(f"{u.key_id}  month={u.month}  used={u.used}  cap={cap}"
              f"{rem}  plan={u.plan}{rev}")
        return 0

    if args.cmd == "export":
        meter = Meter(args.keys, db=args.db)
        print(meter.export(month=args.month, fmt=args.fmt), end="")
        if args.fmt == "json":
            print()
        # An invoice run is exactly when someone must be told that counts
        # exist which nobody can honestly be billed for.
        stranded = meter.legacy_usage(month=args.month)
        if stranded:
            total = sum(r["used"] for r in stranded)
            print(f"warning: {len(stranded)} pre-0.1.2 usage row(s) totaling "
                  f"{total} call(s) could not be attributed to a single key "
                  f"(48-bit key_id collision or a deleted key entry) and are "
                  f"NOT in this export. See Meter.legacy_usage().",
                  file=sys.stderr)
        return 0

    return 2  # pragma: no cover


if __name__ == "__main__":
    raise SystemExit(main())
