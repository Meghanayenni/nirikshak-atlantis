"""Typed provenance for platform knowledge (decision D11).

A platform default is the one security claim NIRIKSHAK makes with **no
configuration line to cite** — the premise is that the directive is absent — so
the provenance is the entire justification for it. These tests check that an
unsourced claim is unconstructable rather than merely discouraged.

The bar the old contract set: `citation: str = Constraint(min_length=1)`. The
string `"general knowledge"` cleared it.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from api.models.enums import PlatformSourceType, ProvenanceStatus
from api.models.pack import PlatformCapability, PlatformDefault, PlatformProvenance
from tests.fixtures.platform import (
    asserted_provenance,
    sourced_capability,
    sourced_default,
    sourced_provenance,
)


def test_sourced_provenance_records_every_required_part() -> None:
    """D11's minimum: platform, source type, identifier, locator, status."""
    p = sourced_provenance()

    assert p.platform
    assert p.source_type is PlatformSourceType.VENDOR_DOCUMENTATION
    assert p.source_id
    assert p.locator
    assert p.status is ProvenanceStatus.SOURCED


def test_sourced_provenance_is_admissible() -> None:
    assert sourced_provenance().is_admissible
    assert sourced_default("telnet_enabled", False).is_admissible
    assert sourced_capability("telnet_enabled", True).is_admissible


# ---------------------------------------------------------------------------
# project_asserted — representable, honest, and not admissible
# ---------------------------------------------------------------------------


def test_project_asserted_is_representable() -> None:
    """A claim we cannot source can still be written down and reviewed later."""
    p = asserted_provenance()

    assert p.status is ProvenanceStatus.PROJECT_ASSERTED
    assert p.source_type is PlatformSourceType.PROJECT_ASSERTED


def test_project_asserted_is_not_admissible() -> None:
    """It is not vendor documentation and cannot support a verdict."""
    assert not asserted_provenance().is_admissible


def test_project_asserted_says_so_in_its_own_citation() -> None:
    """Wherever it is displayed, it cannot be mistaken for external verification."""
    cite = asserted_provenance().cite()

    assert "project assertion" in cite.lower()
    assert "not externally verified" in cite.lower()


def test_an_assertion_cannot_be_relabelled_as_sourced() -> None:
    """The biconditional: both halves say project_asserted, or neither does.

    Marking the status `sourced` while the source type is `project_asserted`
    would present our own claim as externally verified — the exact thing D11
    forbids.
    """
    with pytest.raises(ValidationError, match="BOTH source_type and status"):
        PlatformProvenance(
            platform="testvendor/testos",
            source_type=PlatformSourceType.PROJECT_ASSERTED,
            status=ProvenanceStatus.SOURCED,
            source_id="doc",
            locator="§1",
        )


def test_a_sourced_type_cannot_hide_behind_an_asserted_status() -> None:
    """The other direction of the same biconditional."""
    with pytest.raises(ValidationError, match="BOTH source_type and status"):
        PlatformProvenance(
            platform="testvendor/testos",
            source_type=PlatformSourceType.VENDOR_DOCUMENTATION,
            status=ProvenanceStatus.PROJECT_ASSERTED,
        )


# ---------------------------------------------------------------------------
# Sourced claims must actually be findable
# ---------------------------------------------------------------------------


def test_sourced_claim_needs_a_document() -> None:
    with pytest.raises(ValidationError, match="names no document"):
        PlatformProvenance(
            platform="testvendor/testos",
            source_type=PlatformSourceType.VENDOR_DOCUMENTATION,
            status=ProvenanceStatus.SOURCED,
            locator="§4.2",
        )


def test_sourced_claim_needs_a_locator() -> None:
    """'Somewhere in the configuration guide' is not a citation."""
    with pytest.raises(ValidationError, match="no locator"):
        PlatformProvenance(
            platform="testvendor/testos",
            source_type=PlatformSourceType.VENDOR_DOCUMENTATION,
            status=ProvenanceStatus.SOURCED,
            source_id="TestOS Configuration Guide",
        )


@pytest.mark.parametrize("blank", ["", "   ", "\t"])
def test_whitespace_does_not_satisfy_a_locator(blank: str) -> None:
    with pytest.raises(ValidationError, match="no locator"):
        PlatformProvenance(
            platform="testvendor/testos",
            source_type=PlatformSourceType.VENDOR_DOCUMENTATION,
            status=ProvenanceStatus.SOURCED,
            source_id="TestOS Configuration Guide",
            locator=blank,
        )


# ---------------------------------------------------------------------------
# The old escape hatch is closed
# ---------------------------------------------------------------------------


def test_free_text_citation_is_rejected_outright() -> None:
    """`citation="general knowledge"` used to pass every test in the repository."""
    with pytest.raises(ValidationError, match="[Ee]xtra"):
        PlatformDefault(
            field="telnet_enabled",
            value=False,
            citation="general knowledge",  # type: ignore[call-arg]
        )


def test_a_default_cannot_be_built_without_provenance() -> None:
    with pytest.raises(ValidationError, match="provenance"):
        PlatformDefault(field="telnet_enabled", value=False)


def test_a_capability_claim_cannot_be_built_without_provenance() -> None:
    with pytest.raises(ValidationError, match="without provenance"):
        PlatformCapability(field="telnet_enabled", supported=False)


def test_an_undocumented_capability_needs_no_provenance() -> None:
    """Declining to claim is not a claim, so there is nothing to justify."""
    cap = PlatformCapability(field="telnet_enabled")

    assert cap.supported is None
    assert not cap.is_admissible


# ---------------------------------------------------------------------------
# Content policy
# ---------------------------------------------------------------------------


def test_provenance_holds_identifiers_not_prose() -> None:
    """CONTENT_POLICY — identifiers and locators only, never transcribed text.

    There is deliberately no field for the document's wording. The check is on
    the contract's shape rather than on any value, because a field whose purpose
    is to hold prose is what the policy forbids.
    """
    forbidden = {"text", "body", "content", "prose", "excerpt", "quote", "control_text"}
    assert not (forbidden & set(PlatformProvenance.model_fields))
