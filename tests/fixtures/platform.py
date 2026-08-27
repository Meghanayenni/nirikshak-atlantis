"""Builders for platform capability and default knowledge (decisions D11, D13).

These construct **synthetic** platform knowledge for testing the absence rules.
They are not, and must never become, a source of real vendor defaults: the
builtin packs ship no defaults at all precisely because no vendor documentation
has been sourced, and a fixture that invents one would let the test suite prove
behaviour the shipped product does not have.

The `sourced_*` builders name a fictional document on purpose. Their job is to
exercise the admissible branch of the truth table, not to assert anything true
about Cisco IOS.
"""

from __future__ import annotations

from api.models.enums import PlatformSourceType, ProvenanceStatus
from api.models.pack import PlatformCapability, PlatformDefault, PlatformProvenance

TEST_PLATFORM = "testvendor/testos"


def sourced_provenance(
    *,
    platform: str = TEST_PLATFORM,
    source_id: str = "TestOS Configuration Guide (fictional, for tests only)",
    locator: str = "§4.2, table 3",
    versions: str | None = None,
) -> PlatformProvenance:
    """Admissible provenance: a named document with a locator into it."""
    return PlatformProvenance(
        platform=platform,
        source_type=PlatformSourceType.VENDOR_DOCUMENTATION,
        source_id=source_id,
        locator=locator,
        status=ProvenanceStatus.SOURCED,
        applies_to_versions=versions,
    )


def asserted_provenance(*, platform: str = TEST_PLATFORM) -> PlatformProvenance:
    """Inadmissible provenance: NIRIKSHAK's own claim, honestly labelled.

    Representable so it can be recorded and reviewed. It must never produce a
    determinable field — that is the D11 guarantee the tests check.
    """
    return PlatformProvenance(
        platform=platform,
        source_type=PlatformSourceType.PROJECT_ASSERTED,
        status=ProvenanceStatus.PROJECT_ASSERTED,
    )


def sourced_default(field: str, value: object, **kw: object) -> PlatformDefault:
    return PlatformDefault(
        field=field,
        value=value,  # type: ignore[arg-type]
        provenance=sourced_provenance(**kw),  # type: ignore[arg-type]
    )


def asserted_default(field: str, value: object) -> PlatformDefault:
    return PlatformDefault(
        field=field,
        value=value,  # type: ignore[arg-type]
        provenance=asserted_provenance(),
    )


def sourced_capability(field: str, supported: bool) -> PlatformCapability:
    return PlatformCapability(
        field=field,
        supported=supported,
        provenance=sourced_provenance(),
    )


def asserted_capability(field: str, supported: bool) -> PlatformCapability:
    return PlatformCapability(
        field=field,
        supported=supported,
        provenance=asserted_provenance(),
    )


def undocumented_capability(field: str) -> PlatformCapability:
    """An explicit refusal to claim either way. Must resolve as UNKNOWN."""
    return PlatformCapability(field=field)
