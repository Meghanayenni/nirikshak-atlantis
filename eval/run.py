"""The evaluation harness entry point.

    python -m eval.run              print the report
    python -m eval.run --out PATH   also write it to a file

Exit codes are deliberately not tied to how good the numbers are. A harness that
fails the build when accuracy drops invites the accuracy to be improved by
editing the harness. It exits non-zero only when the measurement could not be
made honestly — a label that does not match its file, a sealed split touched, a
manifest that disagrees with the labels.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from eval.errors import EvaluationError
from eval.report import render
from eval.score import score_all

DEFAULT_OUT = Path(__file__).resolve().parent / "reports" / "evaluation.txt"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="eval.run",
        description="Score NIRIKSHAK against hand-authored ground truth (P9).",
    )
    parser.add_argument(
        "--out",
        type=Path,
        nargs="?",
        const=DEFAULT_OUT,
        default=None,
        help=f"also write the report to a file (default {DEFAULT_OUT})",
    )
    args = parser.parse_args(argv)

    try:
        report = render(score_all())
    except EvaluationError as exc:
        print(f"evaluation could not be completed honestly: {exc}", file=sys.stderr)
        return 2

    print(report)

    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(report, encoding="utf-8")
        print(f"written to {args.out}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
