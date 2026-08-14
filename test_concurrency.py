"""Concurrency sanity for arcaeon_meter — two real OS processes hammer the
same meter. Two claims under test:

1. No lost counts: increments from separate processes all land (SQLite WAL
   + BEGIN IMMEDIATE, not read-modify-write in Python).
2. Cap atomicity: with cap=300 and 400 competing attempts, EXACTLY 300 are
   granted — two workers can never both take the last slot.

Run: python test_concurrency.py
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

from arcaeon_meter import Meter
from arcaeon_meter.keys import add_key

WORKER = r"""
import sys
from arcaeon_meter import Meter
keys_path, secret, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
meter = Meter(keys_path)
grants = denials = 0
for _ in range(n):
    r = meter.check(secret)
    if r:
        grants += 1
    else:
        assert r.reason == "over_cap", r.reason
        denials += 1
print(f"grants={grants} denials={denials}")
"""


def _run_workers(keys_path: Path, secret: str, per_worker: int,
                 workers: int = 2) -> "tuple[int, int]":
    procs = [subprocess.Popen(
        [sys.executable, "-c", WORKER, str(keys_path), secret, str(per_worker)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for _ in range(workers)]
    grants = denials = 0
    for p in procs:
        out, err = p.communicate(timeout=120)
        assert p.returncode == 0, f"worker failed: {err}"
        g, d = out.strip().split()
        grants += int(g.split("=")[1])
        denials += int(d.split("=")[1])
    return grants, denials


def test_two_processes_no_lost_counts():
    with tempfile.TemporaryDirectory() as td:
        kp = Path(td) / "keys.json"
        secret, kid = add_key(kp, monthly_cap=10_000)
        meter = Meter(kp)  # also creates the db; workers share it
        con = meter._connect()
        try:
            assert "wal" == con.execute(
                "PRAGMA journal_mode").fetchone()[0].lower()
        finally:
            con.close()
        grants, denials = _run_workers(kp, secret, per_worker=200)
        assert grants == 400 and denials == 0, (grants, denials)
        assert meter.usage(secret).used == 400
    print("PASS two processes x 200 increments -> used=400, zero lost (WAL)")


def test_cap_is_atomic_under_contention():
    with tempfile.TemporaryDirectory() as td:
        kp = Path(td) / "keys.json"
        secret, kid = add_key(kp, monthly_cap=300)
        meter = Meter(kp)
        grants, denials = _run_workers(kp, secret, per_worker=200)
        assert grants == 300, f"cap over/under-shot: {grants} grants"
        assert denials == 100, denials
        assert meter.usage(secret).used == 300
    print("PASS cap=300 vs 400 contending attempts -> exactly 300 grants, "
          "100 typed denials")


if __name__ == "__main__":
    test_two_processes_no_lost_counts()
    test_cap_is_atomic_under_contention()
    print("ALL PASS")
