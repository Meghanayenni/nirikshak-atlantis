"""Evidence contract — the atom every security claim rests on."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from api.models import Evidence, SourceType, sha256_hex


def make(**overrides: object) -> Evidence:
    base: dict[str, object] = {
        "file_id": "file-1",
        "file_path": "corpus/cisco/rtr-core-01.cfg",
        "line_start": 412,
        "line_end": 412,
        "raw_line": "ip ssh version 2",
        "source_type": SourceType.CLI,
    }
    base.update(overrides)
    return Evidence(**base)  # type: ignore[arg-type]


def test_hash_is_derived_from_raw_line() -> None:
    ev = make()
    assert ev.line_sha256 == sha256_hex("ip ssh version 2")


def test_supplied_hash_must_agree_with_text() -> None:
    """Evidence and the text it cites must not be able to drift apart."""
    with pytest.raises(ValidationError, match="does not match raw_line"):
        make(line_sha256="0" * 64)


def test_supplied_correct_hash_is_accepted() -> None:
    assert make(line_sha256=sha256_hex("ip ssh version 2")).line_start == 412


def test_raw_line_may_not_be_empty() -> None:
    """A blank line cannot support a claim."""
    with pytest.raises(ValidationError):
        make(raw_line="")


@pytest.mark.parametrize("bad", [0, -1])
def test_line_numbers_are_one_based(bad: int) -> None:
    with pytest.raises(ValidationError):
        make(line_start=bad, line_end=bad)


def test_line_end_may_not_precede_line_start() -> None:
    with pytest.raises(ValidationError, match="precedes line_start"):
        make(line_start=20, line_end=10)


def test_evidence_is_immutable() -> None:
    ev = make()
    with pytest.raises(ValidationError):
        ev.raw_line = "tampered"  # type: ignore[misc]


def test_unknown_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        make(control_text="verbatim benchmark prose")


def test_citation_formats() -> None:
    assert make().cite() == "corpus/cisco/rtr-core-01.cfg:412"
    assert make(line_start=10, line_end=14).cite().endswith(":10-14")
    assert make(line_start=10, line_end=14).is_multiline


def test_block_path_is_preserved() -> None:
    ev = make(raw_line=" exec-timeout 10 0", block_path=("line vty 0 4",))
    assert ev.block_path == ("line vty 0 4",)
