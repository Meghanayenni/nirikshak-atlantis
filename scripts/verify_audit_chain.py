"""Standalone audit-chain verifier.

Deliberately independent of FastAPI and of the interface: an integrity check
that can only be run through the surface it polices is not much of a check. Run
it from CI, from cron, or from an operator's shell.

    python scripts/verify_audit_chain.py [--db PATH] [--start N] [--end N] [--json]

Exit codes:
    0  chain verified
    1  verification failed
    2  the chain could not be read at all

Note: this log is tamper-EVIDENT, not tamper-proof. See docs/adr/0008.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from api.audit.verify import verify_chain  # noqa: E402
from api.db.connection import connect, table_exists  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify the NIRIKSHAK audit hash chain.")
    parser.add_argument("--db", type=Path, default=None, help="database path")
    parser.add_argument("--start", type=int, default=0, help="first seq to verify")
    parser.add_argument("--end", type=int, default=None, help="last seq to verify")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)

    db_path = args.db
    if db_path is None:
        from api.config import settings

        db_path = settings.db_path

    if not Path(db_path).exists():
        print(f"cannot read chain: no database at {db_path}", file=sys.stderr)
        return 2

    conn = connect(db_path)
    try:
        if not table_exists(conn, "audit_log"):
            print(f"cannot read chain: {db_path} has no audit_log table", file=sys.stderr)
            return 2

        report = verify_chain(conn, start=args.start, end=args.end)
    finally:
        conn.close()

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.summary())
        for failure in report.failures:
            print(f"  {failure}")
        if report.ok:
            print("\nNote: tamper-evident, not tamper-proof — an attacker with")
            print("unrestricted database write access can recompute an unkeyed chain.")

    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
