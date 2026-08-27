"""Create the first administrator account.

Deliberately a script rather than an HTTP endpoint. A bootstrap route has to be
remembered and disabled after first use, and a step that gets forgotten is a step
that becomes a backdoor. Running this requires access to the machine, which is
the right bar for creating the account that can see the whole fleet.

    python scripts/create_admin.py --username alice

The password is read from a prompt, never from an argument: a command line ends
up in shell history and in the process table, where anyone on the host can read
it.

Imports no web framework, like `verify_audit_chain.py`, so an operator can create
an account without starting — or trusting — the interface it will be used
against.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api.config import settings  # noqa: E402
from api.db import users as user_store  # noqa: E402
from api.db.connection import connect, table_exists  # noqa: E402
from api.db.migrate import OPERATIONAL_MIGRATIONS, migrate  # noqa: E402
from api.models.enums import Role  # noqa: E402
from api.security.passwords import MIN_PASSWORD_LENGTH, PasswordError  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a NIRIKSHAK administrator.")
    parser.add_argument("--username", required=True)
    parser.add_argument(
        "--role",
        default=Role.ADMIN.value,
        choices=[r.value for r in Role],
        help="admin by default; 'user' creates an ordinary account",
    )
    args = parser.parse_args()

    conn = connect(settings.db_path)
    try:
        if not table_exists(conn, "app_user"):
            migrate(conn, OPERATIONAL_MIGRATIONS)

        password = getpass.getpass(f"Password for {args.username} (min {MIN_PASSWORD_LENGTH}): ")
        if password != getpass.getpass("Repeat: "):
            print("passwords do not match", file=sys.stderr)
            return 2

        try:
            user = user_store.create_user(conn, args.username, password, role=Role(args.role))
        except user_store.UserExistsError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        except PasswordError as exc:
            print(str(exc), file=sys.stderr)
            return 2

        # The password is not echoed, not returned and not logged.
        print(f"created {user.role.value} {user.username} ({user.user_id})")
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
