"""Pack checksum verification — defect DEF-13, found at P4 and fixed at P11.

For seven phases a pack declared a `checksum` that nothing ever checked, and the
declared values matched no computable digest of anything.
`tests/unit/test_rulepack_loading.py` recorded that as "a mistake worth not
repeating" while the mistake carried on shipping.

It becomes load-bearing at P11 because `api/train/` now writes pack files at
runtime into `packs/trained/`. Nobody reviews those before they are loaded, so
the digest is the only thing between an edited pack and a parser that believes
it.

The acceptance shape below is the one that matters: verify, change one byte,
verification fails, restore the byte, verification succeeds again.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from api.ingest.pack_checksum import (
    PackChecksumError,
    canonical_bytes,
    compute,
    declared,
    stamp,
    verify_bytes,
    verify_file,
)
from api.ingest.packs import PACKS_ROOT, PackLoadError, load_pack, verify_active_checksum
from api.models.enums import PackStatus

PACK_FILES = sorted(PACKS_ROOT.rglob("*.yaml"))


def _pack_ids() -> list[str]:
    return [f"{p.parent.name}/{p.name}" for p in PACK_FILES]


# ---------------------------------------------------------------------------
# The convention
# ---------------------------------------------------------------------------


def test_the_digest_excludes_the_checksum_line() -> None:
    """What makes stamping a fixed point rather than a fight with itself.

    The value being written cannot participate in the value being computed, so a
    pack can be stamped in one pass and re-stamped forever without changing.
    """
    raw = b"vendor: acme\nchecksum: sha256:" + b"0" * 64 + b"\nos_family: os\n"
    assert b"checksum" not in canonical_bytes(raw)
    assert compute(raw) == compute(raw.replace(b"0" * 64, b"f" * 64))


def test_line_endings_do_not_change_the_digest() -> None:
    """A pack written on Windows and one written on Linux are the same pack.

    An integrity check that disagreed about that would report tampering where
    there is none — the false alarm ADR 0007 warns is the worst failure mode an
    integrity mechanism has.
    """
    lf = b"vendor: acme\nchecksum: sha256:" + b"0" * 64 + b"\npatterns: []\n"
    crlf = lf.replace(b"\n", b"\r\n")
    assert compute(lf) == compute(crlf)


def test_stamping_is_idempotent() -> None:
    raw = b"vendor: acme\nchecksum: sha256:" + b"0" * 64 + b"\npatterns: []\n"
    once = stamp(raw)
    assert stamp(once) == once
    assert verify_bytes(once).verified


def test_a_pack_with_no_checksum_line_cannot_be_stamped() -> None:
    """The field is required on an ACTIVE pack and must exist to be filled."""
    with pytest.raises(PackChecksumError, match="declares no"):
        stamp(b"vendor: acme\npatterns: []\n")


def test_a_pack_declaring_no_checksum_reports_that_rather_than_failing() -> None:
    result = verify_bytes(b"vendor: acme\npatterns: []\n")
    assert not result.is_declared
    assert not result.verified
    assert "declares no checksum" in result.describe()


# ---------------------------------------------------------------------------
# Every shipped pack verifies
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", PACK_FILES, ids=_pack_ids())
def test_every_builtin_pack_verifies(path: Path) -> None:
    """Including the deprecated ones.

    A deprecated pack is a rollback target (D51): pointing the activation record
    back at it makes it the pack in force again, and it has to verify then. A
    superseded pack is not a dead file.
    """
    result = verify_file(path)
    assert result.verified, result.describe()


# ---------------------------------------------------------------------------
# The acceptance shape: verify, tamper, fail, restore, verify
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", PACK_FILES, ids=_pack_ids())
def test_one_changed_byte_breaks_verification_and_restoring_it_repairs(
    path: Path, tmp_path: Path
) -> None:
    """The whole point, run against every pack the repository ships.

    Copied to a temporary file first: this test must never leave a corrupted pack
    behind if it fails halfway.
    """
    original = path.read_bytes()
    working = tmp_path / path.name
    working.write_bytes(original)

    # 1. verify succeeds with the correct digest
    assert verify_file(working).verified

    # 2. change one byte of content — the vendor name's first character
    tampered = original.replace(b"vendor: ", b"vendor: x", 1)
    assert tampered != original
    working.write_bytes(tampered)

    # 3. verification fails
    result = verify_file(working)
    assert not result.verified
    assert "has changed since it was stamped" in result.describe()

    # 4. restore the byte
    working.write_bytes(original)

    # 5. verification succeeds again
    assert verify_file(working).verified


def test_tampering_with_the_checksum_line_itself_is_detected(tmp_path: Path) -> None:
    """Editing the claim rather than the content fails just as loudly."""
    path = PACK_FILES[0]
    raw = path.read_bytes()
    good = declared(raw)
    assert good is not None

    forged = raw.replace(good.encode(), b"sha256:" + b"a" * 64)
    working = tmp_path / path.name
    working.write_bytes(forged)

    assert not verify_file(working).verified


# ---------------------------------------------------------------------------
# Loading fails closed
# ---------------------------------------------------------------------------


def test_an_active_pack_that_does_not_verify_refuses_to_load(tmp_path: Path) -> None:
    """Fail closed, and fail loudly (D47).

    Skipping the offending pack and carrying on would leave a platform silently
    unparsed, which reads downstream as a device with no security configuration
    rather than as an integrity failure — a mis-parse arriving dressed as a fact.
    """
    source = next(p for p in PACK_FILES if load_pack(p).status is PackStatus.ACTIVE)
    working = tmp_path / source.name
    working.write_bytes(source.read_bytes().replace(b"os_family: ", b"os_family: ", 1))

    pack = load_pack(working)
    verify_active_checksum(pack, working)  # unmodified: fine

    working.write_bytes(source.read_bytes() + b"\n# an unreviewed addition\n")
    with pytest.raises(PackChecksumError, match="refusing to load ACTIVE pack"):
        verify_active_checksum(load_pack(working), working)


def test_a_draft_pack_is_not_checksum_gated(tmp_path: Path) -> None:
    """A draft is still being edited.

    Demanding a stamp on every intermediate save would make the stamp a
    formality — something you satisfy rather than something that attests.
    """
    source = PACK_FILES[0]
    raw = source.read_bytes().replace(b"status: active", b"status: draft")
    raw = raw.replace(b"status: deprecated", b"status: draft")
    working = tmp_path / source.name
    working.write_bytes(raw + b"\n# edited while drafting\n")

    pack = load_pack(working)
    assert pack.status is PackStatus.DRAFT
    verify_active_checksum(pack, working)  # does not raise


def test_the_loader_surfaces_a_checksum_failure_rather_than_a_parse_error() -> None:
    """The error must name the real problem.

    `PackChecksumError` is not a `PackLoadError`: an unverifiable pack is an
    integrity event, and collapsing it into "could not read the file" would send
    whoever is on call looking at YAML syntax.
    """
    assert not issubclass(PackChecksumError, PackLoadError)
