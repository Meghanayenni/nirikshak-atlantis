"""What an absent directive means — the whole of decision D11/D13, in one table.

Most non-compliance is a line that is *not there*. A hardening directive may be
missing because the platform already does it by default, or because someone
removed it: opposite conclusions from identical evidence. The Concept Report
calls this the single distinction that separates a usable audit from a
misleading one, and this module is where it is decided.

The table, in full:

    parse       capability        default          →  state
    ---------------------------------------------------------------------
    matched     —                 —                →  PRESENT      (untouched)
    no match    supported: false  —                →  ABSENT_UNSUPPORTED
    no match    supported: true   admissible       →  ABSENT_DEFAULT
    no match    supported: true   inadmissible     →  UNKNOWN / no_match
    no match    supported: true   none             →  UNKNOWN / no_match
    no match    undocumented      —                →  UNKNOWN / capability_unknown
    no pattern  —                 —                →  key absent (reads UNKNOWN)

Three properties hold across every row, and each is a Rule 3 obligation:

**Undocumented never becomes "unsupported".** A missing capability entry is
`None`, not `False`. Reading it as `False` would turn every unasked question into
ABSENT_UNSUPPORTED, which a rule may legitimately treat as NOT_APPLICABLE — so
ignorance would silently become a pass.

**Inadmissible provenance abstains.** A default whose provenance is
`project_asserted`, or whose citation cannot be looked up, is not evidence.
It is recorded and visible, and it produces UNKNOWN.

**Nothing here knows what any field means.** There is no vendor name, no OS
family and no canonical field name anywhere in this module. Every input is pack
data. That is Rule 5: teaching NIRIKSHAK a platform's defaults is a data change.
"""

from __future__ import annotations

from typing import Any

from api.models.enums import ConfidenceMethod, FieldState, UnknownReason
from api.models.field import Field, platform_default_confidence
from api.models.pack import PlatformCapability, PlatformDefault, VendorPack


def resolve_absent_field(
    field_name: str,
    pack: VendorPack,
) -> Field[Any]:
    """Decide what the absence of `field_name` means on this platform.

    Called only when the pack declared a pattern for the field and no line
    matched — so the directive is genuinely absent from this configuration,
    rather than being something the packs cannot read at all. Those two are
    different claims and P4 already keeps them apart by key presence.
    """
    capability = pack.capability_for(field_name)

    if _is_undocumented(capability):
        # The honest answer to a question we never sourced. Deliberately not
        # ABSENT_UNSUPPORTED: that would be an assumption in the direction that
        # happens to be convenient.
        return Field[Any].unknown(
            UnknownReason.CAPABILITY_UNKNOWN,
            confidence_method=ConfidenceMethod.DETERMINISTIC,
        )

    assert capability is not None  # narrowed by _is_undocumented
    if capability.supported is False:
        return _absent_unsupported(capability)

    default = pack.default_for(field_name)
    if default is None or not default.is_admissible:
        # Either nothing documents what happens when the directive is absent, or
        # what documents it is our own assertion. Both abstain. An inadmissible
        # default is still visible in the pack for a reviewer to source later.
        return Field[Any].unknown(
            UnknownReason.NO_MATCH,
            confidence_method=ConfidenceMethod.DETERMINISTIC,
        )

    return _absent_default(default)


def _is_undocumented(capability: PlatformCapability | None) -> bool:
    """No entry at all, or an entry that declines to claim either way.

    Both mean the same thing — we have not established whether this platform can
    express this control — so they resolve identically rather than the absent
    entry being treated as more certain than the explicit abstention.
    """
    return capability is None or capability.supported is None


def _absent_unsupported(capability: PlatformCapability) -> Field[Any]:
    """The platform cannot express this control, and something sourced says so.

    Carries no value, which the contract enforces: there is nothing to report a
    value *of*. The citation travels in `default_ref` so a report can show why
    the control was not evaluated rather than leaving a silent gap.
    """
    if not capability.is_admissible:
        # Support was claimed, but on provenance that cannot carry a verdict.
        return Field[Any].unknown(
            UnknownReason.CAPABILITY_UNKNOWN,
            confidence_method=ConfidenceMethod.DETERMINISTIC,
        )

    assert capability.provenance is not None  # implied by is_admissible
    return Field[Any](
        value=None,
        state=FieldState.ABSENT_UNSUPPORTED,
        confidence=platform_default_confidence(),
        confidence_method=ConfidenceMethod.PLATFORM_DEFAULT,
        default_ref=capability.provenance.cite(),
    )


def _absent_default(default: PlatformDefault) -> Field[Any]:
    """The directive is absent and the platform's documented default applies.

    No `Evidence`, because there is no line to cite — that is the premise. The
    contract requires `default_ref` instead, so the claim still carries its
    justification and Rule 2 is satisfied by the documentation rather than by the
    configuration.

    The confidence is the configured D13 value, applied only after provenance has
    already qualified the claim. It is a single number for every accepted
    default, not something the pack chose.
    """
    return Field[Any](
        value=default.value,
        state=FieldState.ABSENT_DEFAULT,
        confidence=platform_default_confidence(),
        confidence_method=ConfidenceMethod.PLATFORM_DEFAULT,
        default_ref=default.provenance.cite(),
    )


def is_platform_derived(field: Field[Any]) -> bool:
    """Whether this field came from platform knowledge rather than from the file.

    A report and an audit record must be able to tell the two apart: "we observed
    telnet enabled on line 17" and "this platform documents telnet as disabled by
    default" are different kinds of claim, and only one of them cites the
    operator's own configuration.
    """
    return field.confidence_method is ConfidenceMethod.PLATFORM_DEFAULT
