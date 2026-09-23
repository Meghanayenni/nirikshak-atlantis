"""Fetch an official framework catalog and derive its control-identifier index.

**This is a sourcing step, not part of the product.** It lives in `scripts/`
because it makes a network request, and Rule 6 says the running system is
offline-first: nothing under `api/` may fetch anything, and no audit depends on
this having been run. An operator on an airgapped network supplies the catalog
file by hand and points `--catalog` at it instead.

What it produces is the index under `rules/frameworks/`: the catalog's own
sha256, its edition, and the sorted list of control identifiers it contains. The
catalog itself is deliberately **not** committed — see ADR 0035 on the
redistribution question, which is recorded as open rather than answered.

Usage:

    python scripts/fetch_framework_catalog.py nist --out /path/to/catalog.json
    python scripts/fetch_framework_catalog.py nist --catalog /path/to/catalog.json --write-index
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
INDEX_DIR = REPO_ROOT / "rules" / "frameworks"

SOURCES: dict[str, dict[str, str]] = {
    "nist": {
        "framework": "nist",
        "index_name": "nist-sp-800-53-rev5.index.yaml",
        "document": "NIST SP 800-53 Rev 5 — OSCAL catalog",
        "url": (
            "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
            "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
        ),
    }
}
"""Catalogs this script knows how to read.

DISA STIGs are published as XCCDF on the DoD Cyber Exchange and are **not**
here: the download index is rendered client-side and no direct file URL could be
resolved from this environment. Guessing a filename is the same failure as
guessing a control identifier, in URL form. See ADR 0035.
"""


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def download(url: str, out: Path) -> Path:
    request = urllib.request.Request(url, headers={"User-Agent": "nirikshak-sourcing"})
    with urllib.request.urlopen(request, timeout=300) as response:  # noqa: S310
        out.write_bytes(response.read())
    return out


# ---------------------------------------------------------------------------
# NIST OSCAL
# ---------------------------------------------------------------------------


def _oscal_controls(node: dict[str, Any], out: list[dict[str, Any]]) -> None:
    for control in node.get("controls", []):
        out.append(control)
        _oscal_controls(control, out)


def read_nist_oscal(path: Path) -> tuple[str, list[str], list[str]]:
    """(edition, live control labels, withdrawn control labels).

    Withdrawn controls are separated rather than dropped. `AC-17(8)` and
    `AU-8(1)` are both withdrawn in Rev 5 and both are exactly what somebody
    would write from memory for "disable nonsecure protocols" and "synchronise
    with an authoritative time source" — so the index has to be able to say
    *that identifier exists and you may not map to it*, which is a stronger
    statement than its absence.
    """
    catalog = json.loads(path.read_text(encoding="utf-8"))["catalog"]
    edition = catalog["metadata"]["version"]

    found: list[dict[str, Any]] = []
    for group in catalog.get("groups", []):
        _oscal_controls(group, found)

    live: list[str] = []
    withdrawn: list[str] = []
    for control in found:
        props = {p["name"]: p.get("value") for p in control.get("props", [])}
        label = props.get("label") or control["id"].upper()
        (withdrawn if props.get("status") == "withdrawn" else live).append(label)

    return edition, sorted(set(live)), sorted(set(withdrawn))


READERS = {"nist": read_nist_oscal}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", choices=sorted(SOURCES))
    parser.add_argument("--out", type=Path, help="download the catalog to this path")
    parser.add_argument("--catalog", type=Path, help="read an already-obtained catalog")
    parser.add_argument(
        "--write-index", action="store_true", help="write the index under rules/frameworks/"
    )
    args = parser.parse_args(argv)

    spec = SOURCES[args.source]

    catalog = args.catalog
    if catalog is None:
        if args.out is None:
            parser.error("give --catalog to read a local file, or --out to download one")
        print(f"fetching {spec['url']}", file=sys.stderr)
        catalog = download(spec["url"], args.out)

    digest = sha256_of(catalog)
    edition, live, withdrawn = READERS[args.source](catalog)

    print(f"document : {spec['document']}")
    print(f"edition  : {edition}")
    print(f"sha256   : {digest}")
    print(f"controls : {len(live)} live, {len(withdrawn)} withdrawn")

    if not args.write_index:
        return 0

    index = {
        "framework": spec["framework"],
        "document": spec["document"],
        "edition": edition,
        "source_url": spec["url"],
        "catalog_sha256": digest,
        "controls": live,
        "withdrawn": withdrawn,
    }
    target = INDEX_DIR / spec["index_name"]
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        "# Derived by scripts/fetch_framework_catalog.py. Identifiers only — no\n"
        "# control text, per docs/CONTENT_POLICY.md. Do not hand-edit.\n"
        + yaml.safe_dump(index, sort_keys=False, default_flow_style=False, width=100),
        encoding="utf-8",
    )
    print(f"wrote {target}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
