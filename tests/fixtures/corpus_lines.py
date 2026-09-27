"""Development lines, as a person reads them and as the parser reads them.

Three tests re-check that every pack example and every similarity seed is a line
someone read in a development configuration. They must agree on what counts as
a line, so they share this.

A pattern matches the parsed statement. In JunOS brace form that drops the
structural `;` or `{` — the line `telnet;` is the statement `telnet` — so an
example written in the form its pattern matches is admitted for exactly the
files the parser reads as brace, decided the way the parser decides it
(ADR 0065). Every other line is admitted only as written.
"""

from __future__ import annotations

from pathlib import Path

from api.models.enums import SyntaxMode
from api.parse.block_parser import _brace_text
from api.parse.service import ALTERNATE_SURFACES, BRACE_OPENER


def lines_of(text: str, os_family: str | None) -> set[str]:
    """Every non-blank stripped line, plus its brace statement form where apt."""
    stripped = {ln.strip() for ln in text.splitlines() if ln.strip()}
    braced = ALTERNATE_SURFACES.get(os_family or "") is SyntaxMode.BRACE
    if braced and BRACE_OPENER.search(text):
        return stripped | ({_brace_text(ln) for ln in stripped} - {""})
    return stripped


OS_FAMILY_BY_VENDOR_DIR = {"cisco": None, "arista": "eos", "juniper": "junos"}
"""A vendor directory's brace-capable family. Cisco has two families and
neither has a brace surface, so it needs no answer."""


def development_lines(corpus: Path) -> set[str]:
    """Every line of every file under `corpus/<vendor>/dev/`."""
    lines: set[str] = set()
    for vendor_dir in sorted(corpus.iterdir()):
        dev = vendor_dir / "dev"
        if not dev.is_dir():
            continue
        family = OS_FAMILY_BY_VENDOR_DIR.get(vendor_dir.name)
        for path in sorted(dev.iterdir()):
            text = path.read_text(encoding="utf-8", errors="replace")
            lines |= lines_of(text, family)
    return lines
