"""Where device identity comes from, and what no configuration carries.

Problem Statement 26155 names serial numbers and hardware details as report
deliverables. The contract, the database column and the evidence plumbing have
existed since P3; what was missing was a pattern reading a line a device
actually writes.

Two separate facts, and they need keeping apart:

**The model is readable on Arista.** EOS writes
`! device: <name> (<model>, EOS-<version>)` at the top of every
`show running-config`, and all four Arista corpus files carry it.

**The serial is readable nowhere.** Not one running-config in this corpus, on
any of the four platforms, carries a serial number — it is inventory data that
lives in `show version` and `show inventory`, not in a configuration export.
That is a platform limit rather than a gap in the packs, and declaring a pattern
for it would put a regex in a pack that no device could satisfy.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from api.ingest.device_identity import extract_identity
from api.ingest.packs import find_pack, load_active_packs
from api.models.enums import FieldState

CORPUS = Path("corpus")
PLATFORMS = {
    "cisco": ("cisco", "ios"),
    "arista": ("arista", "eos"),
    "juniper": ("juniper", "junos"),
}


@pytest.fixture(scope="module")
def packs():
    return load_active_packs(use_cache=False)


def identify(path: Path, packs):
    vendor, os_family = PLATFORMS[path.parts[1]]
    pack = find_pack(vendor, os_family, packs)
    assert pack is not None
    return pack, extract_identity(
        pack, path.read_text(encoding="utf-8").splitlines(), file_id=path.name, file_path=str(path)
    )


def corpus_files() -> list[Path]:
    return sorted(
        p
        for p in CORPUS.rglob("*")
        if p.suffix in (".cfg", ".conf") and "holdout" not in p.parts and p.parts[1] in PLATFORMS
    )


# ---------------------------------------------------------------------------
# The model, where a device writes it
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("filename", "model"),
    [
        ("sw-leaf-01.cfg", "DCS-7050SX3-48YC8"),
        ("sw-spine-01.cfg", "DCS-7280CR3-32P4"),
        ("dc1-spine-01.cfg", "vEOS"),
    ],
)
def test_the_arista_model_is_read_from_the_header_eos_writes(
    packs, filename: str, model: str
) -> None:
    path = next(p for p in corpus_files() if p.name == filename)
    _, identity = identify(path, packs)

    assert identity.model is not None
    assert identity.model.value == model
    assert identity.model.state is FieldState.PRESENT


def test_the_model_cites_the_line_it_was_read_from(packs) -> None:
    """Rule 2 applies to identity as much as to a verdict."""
    path = next(p for p in corpus_files() if p.name == "sw-leaf-01.cfg")
    _, identity = identify(path, packs)

    evidence = identity.model.evidence[0]
    assert evidence.line_start == 1
    assert evidence.raw_line.startswith("! device: sw-leaf-01")


def test_the_model_and_version_come_from_one_line_without_confusing_them(packs) -> None:
    """`(DCS-7050SX3-48YC8, EOS-4.29.2F)` — two captures, one header."""
    path = next(p for p in corpus_files() if p.name == "sw-leaf-01.cfg")
    _, identity = identify(path, packs)

    assert identity.model.value == "DCS-7050SX3-48YC8"
    assert identity.os_version.value == "4.29.2F"


# ---------------------------------------------------------------------------
# The model, where no device writes it
# ---------------------------------------------------------------------------


def test_cisco_no_longer_reports_a_model(packs) -> None:
    """1.2.0 read `^! model (\\S+)`, which matched an annotation, not a device.

    Cisco's `show running-config` does not emit the hardware model. The only
    line in the world matching that pattern is one somebody typed into
    `rtr-core-01.cfg`, and reporting it as observed device identity — with a
    citation — is the shape Rule 2 exists to prevent, arriving through the one
    path ADR 0011 deliberately left open to comments.

    An honest UNKNOWN replaces a value that was right about a fixture and wrong
    about every real device.
    """
    cisco = [p for p in corpus_files() if p.parts[1] == "cisco"]
    assert cisco

    for path in cisco:
        _, identity = identify(path, packs)
        assert identity.model is None or identity.model.state is not FieldState.PRESENT, (
            f"{path.name} reports a model, and no Cisco configuration export carries one"
        )


def test_no_shipped_pack_declares_a_model_pattern_reading_an_annotation(packs) -> None:
    """The specific line, named, so reinstating it fails here."""
    for pack in packs:
        for pattern in pack.identity:
            assert "! model " not in pattern.match.pattern, (
                f"{pack.pack_id} reads a model from a line no device emits"
            )


# ---------------------------------------------------------------------------
# The serial, which nothing carries
# ---------------------------------------------------------------------------


def test_no_corpus_configuration_carries_a_serial(packs) -> None:
    """The measurement behind the decision not to author a pattern.

    Stated as a test rather than as a sentence in a document, so that a corpus
    file which *does* carry one — a `show version` capture, a vendor export in a
    different format — fails here and prompts the pattern rather than sitting
    unnoticed.
    """
    reporting = [
        path.name
        for path in corpus_files()
        if (identity := identify(path, packs)[1]).serial is not None
        and identity.serial.state is FieldState.PRESENT
    ]
    assert reporting == [], (
        f"these files carry a serial and no pack reads it: {reporting}. "
        "A pattern is now worth authoring."
    )


def test_no_pack_declares_a_serial_pattern(packs) -> None:
    """A regex no device could satisfy looks like support and produces UNKNOWN.

    **Expected to be deleted** by whoever obtains a configuration export that
    carries a serial, together with the platform documentation saying it does.
    """
    declared = {
        pack.pack_id: [p.field for p in pack.identity if p.field == "serial"] for pack in packs
    }
    assert all(not fields for fields in declared.values()), (
        f"a serial pattern was added without a file to verify it against: {declared}"
    )


def test_the_serial_field_still_exists_and_abstains(packs) -> None:
    """The deliverable is not dropped; it abstains, which is a different thing."""
    path = next(p for p in corpus_files() if p.name == "sw-leaf-01.cfg")
    _, identity = identify(path, packs)

    assert identity.serial is None or identity.serial.state is not FieldState.PRESENT
