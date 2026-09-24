"""A field the input cannot carry is not a field nobody parsed.

`DeviceIdentity.serial` is `None` on every device NIRIKSHAK has read, and until
P18 the repository filed that beside its parsing gaps. It is not one: a serial
appears in `show version` and `show inventory` output, not in a configuration
export, so no pattern over this input could ever match.

The distinction matters because the two have different fixes. A parsing gap is
closed by authoring a pattern. This is closed by accepting a second input type,
and until somebody does, a `serial` pattern would be a regex in a pack that no
input can satisfy — the failure DEVELOPER_GUIDE.md §3 names directly.
"""

from __future__ import annotations

import pytest

from api.ingest.packs import load_active_packs
from api.models.enums import SourceType
from api.models.source_limits import NOT_DETERMINABLE, limited_fields, not_determinable


def test_the_serial_is_recorded_as_undeterminable_from_a_configuration() -> None:
    reason = not_determinable("serial", SourceType.CLI)

    assert reason is not None
    assert "show version" in reason
    assert "second input type" in reason, (
        "the record must name the fix, or it is only a restatement of the absence"
    )


def test_a_field_with_no_limit_returns_none() -> None:
    """Absence of a limit is not a promise of a value.

    `hostname` is read on most devices and missing on some, for ordinary
    reasons. Nothing here claims it cannot be read.
    """
    assert not_determinable("hostname", SourceType.CLI) is None
    assert not_determinable("model", SourceType.CLI) is None


def test_no_limit_is_claimed_for_an_input_type_that_is_not_supported() -> None:
    """XML and JSON ingestion are not built, so no claim is made about them.

    Recording a limit for an input nothing reads would be asserting something
    about a code path that does not exist — and it would look like coverage.
    """
    assert limited_fields(SourceType.XML) == frozenset()
    assert limited_fields(SourceType.JSON) == frozenset()


def test_the_table_stays_small_and_deliberate() -> None:
    """An entry here says NO pack will ever read this field from this input.

    That is a stronger claim than "nobody has written the pattern yet", and a
    table that grew casually would start absorbing ordinary parsing gaps, which
    belong in SOURCING_BACKLOG where somebody can close them.
    """
    assert limited_fields(SourceType.CLI) == {"serial"}
    for reasons in NOT_DETERMINABLE.values():
        for field, reason in reasons.items():
            assert len(reason.split()) >= 15, f"{field} is limited without an explanation"


@pytest.mark.parametrize("field", ["serial"])
def test_no_shipped_pack_declares_a_pattern_for_a_limited_field(field: str) -> None:
    """The consequence, asserted against the packs rather than trusted.

    Four packs ship identity patterns. None may declare one for a field the
    input cannot carry, because such a pattern could only ever be dead weight
    that makes the field look supported.
    """
    offenders = [
        f"{pack.pack_id} declares an identity pattern for {field!r}"
        for pack in load_active_packs(use_cache=False)
        for pattern in pack.identity
        if pattern.field == field
    ]
    assert offenders == [], "\n".join(offenders)
