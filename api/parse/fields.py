"""Turning pattern matches into canonical fields, or into an honest abstention.

The rules here are uniform — no field defines its own special case — and they all
resolve the same question: does the configuration say something we can stand
behind, and if not, why not.

The one that matters most is disagreement. Two matches with different values is
not a tie to be broken by order of appearance; it is a configuration we cannot
read confidently, and the field abstains **carrying both citations** so the
operator can see exactly what we could not resolve.
"""

from __future__ import annotations

from typing import Any

from api.models.enums import CastType, ConfidenceMethod, FieldState, PatternSource, UnknownReason
from api.models.field import Field, FieldProvenance
from api.models.pack import PatternDef, VendorPack
from api.models.parsing import FieldMatch
from api.parse.casts import is_multi_valued

DETERMINISTIC_CONFIDENCE = 1.0
"""A deterministic pattern matched or it did not (decision D6). There is no
partial match to express, so a successful parse is worth exactly 1.0 — and the
pack contract rejects any other value rather than letting YAML say otherwise."""


def _pattern_source(pack: VendorPack, pattern_id: str) -> PatternSource:
    """The source declared by the pattern that actually fired (defect DEF-10).

    This was hard-coded to `BUILTIN`, which was true of every pattern in the
    repository until P11 and false the moment the first administrator confirmed
    one. `FieldProvenance.source` is documented as recording *whether a human
    vetted it*; reporting a compiled confirmation as vendor-shipped erases the
    only distinction the learning loop creates, and an operator could not tell a
    mapping NIRIKSHAK shipped from one their colleague confirmed last Tuesday.
    """
    for pattern in pack.patterns:
        if pattern.id == pattern_id:
            return pattern.source
    return PatternSource.BUILTIN


def _method_for(source: PatternSource) -> ConfidenceMethod:
    """Which confidence population a match belongs to (D48).

    Both are exact-1.0 populations (`EXACT_CONFIDENCE_POPULATIONS`, decision D6):
    a pattern either matched or it did not, and a human either confirmed a
    mapping or did not. They are kept apart because they are different *kinds* of
    claim — one rests on a vendor pack somebody reviewed, the other on a named
    administrator's judgement recorded in the audit chain — and R7 exists to stop
    populations being pooled just because they share a numeric range.

    Neither is model-derived, so no verdict changes: a compiled pattern reaches a
    field by matching text deterministically, exactly as a builtin one does.
    """
    if source is PatternSource.ADMIN_TRAINED:
        return ConfidenceMethod.ADMIN_CONFIRMED
    return ConfidenceMethod.DETERMINISTIC


def _provenance(pack: VendorPack, pattern_id: str) -> FieldProvenance:
    return FieldProvenance(
        pack_id=pack.pack_id,
        pack_version=pack.pack_version,
        pattern_id=pattern_id,
        source=_pattern_source(pack, pattern_id),
    )


def _cast_of(pack: VendorPack, field_name: str) -> CastType:
    for pattern in pack.patterns:
        if pattern.field == field_name:
            return pattern.capture.cast
    return CastType.STR


def build_field(
    field_name: str,
    matches: list[FieldMatch],
    pack: VendorPack,
) -> Field[Any]:
    """One canonical field from its matches, abstaining where it must."""
    cast = _cast_of(pack, field_name)
    evidence = tuple(m.evidence for m in matches)

    if not matches:
        # The pack has a pattern for this field and nothing matched, so the
        # directive is absent from this configuration. P5 decides what absence
        # means for the platform; parsing does not guess.
        return Field[Any].unknown(
            UnknownReason.NO_MATCH,
            confidence_method=ConfidenceMethod.DETERMINISTIC,
        )

    provenance = _provenance(pack, matches[0].pattern_id)
    method = _method_for(_pattern_source(pack, matches[0].pattern_id))

    if is_multi_valued(cast):
        # Repetition is accumulation: two `ntp server` lines are two servers.
        # Order follows the source, and duplicates are kept rather than folded —
        # a configuration listing the same server twice really does say that.
        values = [m.value for m in matches]
        return Field[Any](
            value=values,
            state=FieldState.PRESENT,
            confidence=DETERMINISTIC_CONFIDENCE,
            confidence_method=method,
            evidence=evidence,
            provenance=provenance,
        )

    distinct = {m.value for m in matches}

    if len(distinct) > 1:
        # Two lines disagree. Picking one by position would be inventing an
        # answer the configuration does not give, so the field abstains and
        # cites every line that contributed to the disagreement.
        return Field[Any](
            value=None,
            state=FieldState.UNKNOWN,
            confidence=0.0,
            confidence_method=method,
            unknown_reason=UnknownReason.CONFLICTING_EVIDENCE,
            evidence=evidence,
            provenance=provenance,
        )

    # One value, however many lines said it. Every citation is kept so a report
    # can show all of them.
    return Field[Any](
        value=matches[0].value,
        state=FieldState.PRESENT,
        confidence=DETERMINISTIC_CONFIDENCE,
        confidence_method=method,
        evidence=evidence,
        provenance=provenance,
    )


def declared_fields(pack: VendorPack) -> list[str]:
    """Canonical fields this pack claims to be able to read.

    A field the pack declares but does not find is genuinely absent from the
    configuration. A field the pack never declares is one we cannot parse at all
    — a different thing, and one that routes to training rather than to a
    platform default. Key presence in the resulting map is what distinguishes
    them, without needing a new abstention reason.
    """
    seen: list[str] = []
    for pattern in pack.patterns:
        if pattern.field not in seen:
            seen.append(pattern.field)
    return seen


def build_fields(by_field: dict[str, list[FieldMatch]], pack: VendorPack) -> dict[str, Field[Any]]:
    """Every field the pack declares, present or abstaining."""
    return {name: build_field(name, by_field.get(name, []), pack) for name in declared_fields(pack)}


def patterns_for(pack: VendorPack, field_name: str) -> list[PatternDef]:
    return [p for p in pack.patterns if p.field == field_name]
