"""Fetch an official framework catalog and derive its control-identifier index.

**This is a sourcing step, not part of the product.** It lives in `scripts/`
because it makes a network request, and Rule 6 says the running system is
offline-first: nothing under `api/` may fetch anything, and no audit depends on
this having been run. An operator on an airgapped network supplies the catalog
file by hand and points `--catalog` at it instead.

What it produces is the index under `rules/frameworks/`: the catalog's own
sha256, its edition, the platform the edition covers, and the sorted list of
control identifiers it contains.

**Where the source document lives differs per framework, and that is the point
of ADR 0052.** The NIST catalog is not committed (ADR 0035, redistribution left
open). The DISA STIG XCCDF *is* committed, under `docs/sources/disa/`, because it
is a US Government work published for public download — so its index can be
re-derived from a file in the tree. The CIS Benchmark must **never** be
committed: its own terms say it may not be hosted on a third-party site, and
this repository has a public remote. It is read from an operator-supplied path
and only its recommendation *numbers* are written out.

Usage:

    python scripts/fetch_framework_catalog.py nist --out /path/to/catalog.json
    python scripts/fetch_framework_catalog.py nist --catalog /path/to/catalog.json --write-index
    python scripts/fetch_framework_catalog.py stig --write-index
    python scripts/fetch_framework_catalog.py cis --catalog /outside/the/tree/cis.pdf --write-index
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Any

import yaml
from lxml import etree

REPO_ROOT = Path(__file__).resolve().parent.parent
INDEX_DIR = REPO_ROOT / "rules" / "frameworks"

STIG_HELD_AT = "docs/sources/disa/U_Cisco_IOS-XE_Router_NDM_STIG_V3R7_Manual-xccdf.xml"

SOURCES: dict[str, dict[str, Any]] = {
    "nist": {
        "framework": "nist",
        "index_name": "nist-sp-800-53-rev5.index.yaml",
        "document": "NIST SP 800-53 Rev 5 — OSCAL catalog",
        "url": (
            "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
            "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
        ),
    },
    "stig": {
        "framework": "stig",
        "index_name": "disa-stig-cisco-ios-xe-router-ndm.index.yaml",
        "document": "DISA Cisco IOS XE Router NDM STIG — XCCDF manual benchmark",
        "held_at": STIG_HELD_AT,
        "source_note": (
            "Obtained by hand from the DoD Cyber Exchange public STIG library as "
            "U_Cisco_IOS-XE_Router_Y26M04_STIG.zip (sha256 "
            "01900ad03d8972698160db7c1fdfc71b64a3c7188ee53c4f1047fc827986f36d); the "
            "XCCDF file inside it is committed at held_at, byte for byte."
        ),
        "covers": {
            "vendor": "cisco",
            "os_family": "ios",
            "os_version": r"^17\.",
            "basis": (
                "The document names Cisco IOS XE routers and states no release. "
                "17.x is the only release family any source in hand ties to IOS XE; "
                "classic IOS 15.x shares os_family 'ios' in NIRIKSHAK and is not "
                "covered. Device role (router or switch) is not determinable."
            ),
        },
    },
    "cis": {
        "framework": "cis",
        "index_name": "cis-cisco-ios-xe-17.index.yaml",
        "document": "CIS Cisco IOS XE 17.x Benchmark",
        "source_note": (
            "Referenced, not held. The benchmark's own terms forbid hosting it on a "
            "third-party site, so the file is read from an operator-supplied path "
            "outside this repository and only recommendation numbers are recorded."
        ),
        "covers": {
            "vendor": "cisco",
            "os_family": "ios",
            "os_version": r"^17\.",
            "basis": (
                "The document's target-technology section names a Cisco router on "
                "IOS XE 17. Classic IOS 15.x shares os_family 'ios' in NIRIKSHAK and is "
                "not covered. Device role (router or switch) is not determinable."
            ),
        },
    },
}
"""Catalogs this script knows how to read.

`covers` is the platform an edition speaks about. NIST SP 800-53 is a control
catalog for any system and declares none. A STIG or a CIS Benchmark is written
for one product, and a mapping from a vendor-neutral NIRIKSHAK rule to one of its
identifiers is true only on that product (ADR 0052).
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


# ---------------------------------------------------------------------------
# DISA STIG (XCCDF 1.1)
# ---------------------------------------------------------------------------


def read_stig_xccdf(path: Path) -> tuple[str, list[str], list[str]]:
    """(edition, STIG IDs, withdrawn) from a manual XCCDF benchmark.

    The identifier is each `Rule`'s `version` element — `CISC-ND-000470` — which
    is what a STIG checklist and an assessor cite. The `SV-…r…_rule` id changes
    with every revision of the rule text and the `V-` group id is not what the
    requirement is known by, so neither is indexed.

    The edition is assembled from the document's own `version` and its
    `release-info` plain-text ("Release: 7 Benchmark Date: 01 Apr 2026"), in the
    form DISA itself uses: `V3R7 (2026-04-01)`. A manual benchmark lists no
    withdrawn requirements, so that list is empty rather than guessed.
    """
    from datetime import datetime

    root = etree.parse(str(path)).getroot()
    ns = {"x": root.nsmap[None]}
    version = root.findtext("x:version", namespaces=ns)
    info = root.findtext("x:plain-text[@id='release-info']", namespaces=ns) or ""
    found = re.search(r"Release:\s*(\d+)\s+Benchmark Date:\s*(\d{1,2} \w{3} \d{4})", info)
    if version is None or found is None:
        raise SystemExit(f"{path.name}: no version or release-info; not a STIG benchmark")
    date = datetime.strptime(found.group(2), "%d %b %Y").date().isoformat()
    edition = f"V{version.strip()}R{found.group(1)} ({date})"

    ids = [
        (rule.findtext("x:version", namespaces=ns) or "").strip()
        for rule in root.iterfind(".//x:Rule", ns)
    ]
    if not ids or any(not i for i in ids):
        raise SystemExit(f"{path.name}: a Rule carries no STIG ID")
    return edition, sorted(set(ids)), []


# ---------------------------------------------------------------------------
# CIS Benchmark (PDF, operator-supplied, never held)
# ---------------------------------------------------------------------------


def _pdf_text(path: Path) -> list[str]:
    """Text of a PDF via poppler's `pdftotext`, which must be on PATH.

    An external tool rather than a Python dependency: this is a sourcing step an
    operator runs once, not part of the product, and adding a PDF library to the
    lock file for it would enlarge the installed surface of every deployment.
    Absent, it **raises** — a reader that returned no identifiers would write an
    index validating nothing, which `CatalogIndex` refuses anyway but should
    never be asked to.
    """
    tool = shutil.which("pdftotext")
    if tool is None:
        raise SystemExit(
            "pdftotext (poppler-utils) is required to read a CIS Benchmark PDF and "
            "was not found on PATH. Nothing was written."
        )
    out = subprocess.run(  # noqa: S603 - fixed argv, operator-supplied path
        [tool, "-enc", "UTF-8", "-layout", str(path), "-"],
        check=True,
        capture_output=True,
    )
    return out.stdout.decode("utf-8").splitlines()


_CIS_HEADER = re.compile(r"^\s*(\d+(?:\.\d+)+)\s+\S")
_CIS_EDITION = re.compile(r"\bv(\d+\.\d+\.\d+)\s*-\s*(\d{2})-(\d{2})-(\d{4})")


def read_cis_pdf(path: Path) -> tuple[str, list[str], list[str]]:
    """(edition, recommendation numbers, withdrawn) from a CIS Benchmark PDF.

    A recommendation is a numbered heading followed within five lines by
    `Profile Applicability:` — which is what distinguishes `2.1.1.2` (a
    recommendation) from `2.1.1` (a section heading) without trusting the table
    of contents' layout. **Only the number is kept.** The heading's words are
    read to find the number and then discarded: CIS titles, rationale, audit and
    remediation text are the benchmark's material, and this repository records
    what was read, never the material (ADR 0052, `docs/CONTENT_POLICY.md`).
    """
    lines = _pdf_text(path)
    found = _CIS_EDITION.search("\n".join(lines[:15]))
    if found is None:
        raise SystemExit(f"{path.name}: no 'vX.Y.Z - MM-DD-YYYY' edition on the cover")
    version, month, day, year = found.groups()
    edition = f"v{version} ({year}-{month}-{day})"

    numbers = [
        match.group(1)
        for i, line in enumerate(lines)
        if (match := _CIS_HEADER.match(line))
        and any("Profile Applicability:" in nxt for nxt in lines[i + 1 : i + 6])
    ]
    return edition, sorted(set(numbers), key=_numeric_key), []


def _numeric_key(number: str) -> tuple[int, ...]:
    return tuple(int(part) for part in number.split("."))


READERS = {"nist": read_nist_oscal, "stig": read_stig_xccdf, "cis": read_cis_pdf}


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
    if catalog is None and "held_at" in spec:
        catalog = REPO_ROOT / spec["held_at"]
    if catalog is None:
        if args.out is None or "url" not in spec:
            parser.error("give --catalog to read a local file, or --out to download one")
        print(f"fetching {spec['url']}", file=sys.stderr)
        catalog = download(spec["url"], args.out)

    if args.source == "cis" and catalog.resolve().is_relative_to(REPO_ROOT):
        # The benchmark may be *referenced by* this repository and never held
        # in it. A copy inside the tree is one `git add .` from a public remote.
        raise SystemExit(
            f"{catalog} is inside the repository. A CIS Benchmark must be read from "
            "outside the tree (ADR 0052); move it and pass that path."
        )

    digest = sha256_of(catalog)
    edition, live, withdrawn = READERS[args.source](catalog)

    print(f"document : {spec['document']}")
    print(f"edition  : {edition}")
    print(f"sha256   : {digest}")
    print(f"controls : {len(live)} live, {len(withdrawn)} withdrawn")

    if not args.write_index:
        return 0

    index: dict[str, Any] = {
        "framework": spec["framework"],
        "document": spec["document"],
        "edition": edition,
    }
    for key in ("url", "held_at", "source_note"):
        if key in spec:
            index["source_url" if key == "url" else key] = spec[key]
    index["catalog_sha256"] = digest
    if "covers" in spec:
        index["covers"] = spec["covers"]
    index["controls"] = live
    index["withdrawn"] = withdrawn
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
