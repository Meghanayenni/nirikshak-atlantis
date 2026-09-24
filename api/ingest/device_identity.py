"""Device identity extraction — deterministic and data-driven (decision D3).

Hostname, model, OS version and serial come from `IdentityPattern` entries in
the vendor pack, using the same `MatchSpec` machinery the parsing patterns use.
No pack, no identity: an UNKNOWN platform yields UNKNOWN identity, because there
is nothing to say where to look.

Each field is a `Field[str]` and abstains independently. A configuration with a
hostname but no serial produces one PRESENT field and one UNKNOWN field — never
an invented serial, and never a partially-filled identity presented as complete.
"""

from __future__ import annotations

import re

from api.models import (
    ConfidenceMethod,
    Evidence,
    Field,
    FieldProvenance,
    FieldState,
    PatternSource,
    SourceType,
    UnknownReason,
)
from api.models.ingestion import DetectedDeviceIdentity
from api.models.pack import IdentityPattern, MatchType, VendorPack

IDENTITY_ORDER = ("hostname", "model", "os_version", "serial", "domain_name")


def _apply(
    pattern: IdentityPattern,
    lines: list[str],
    *,
    file_id: str,
    file_path: str,
    source_type: SourceType,
    pack: VendorPack,
) -> Field[str]:
    """Run one identity pattern over the file, returning a Field either way."""
    if pattern.match.type is not MatchType.REGEX:
        return Field[str].unknown(
            UnknownReason.NO_MATCH,
            confidence_method=ConfidenceMethod.DETERMINISTIC,
        )

    rx = re.compile(pattern.match.pattern)
    for number, line in enumerate(lines, start=1):
        found = rx.search(line)
        if not found:
            continue

        try:
            value = found.group(1) if found.groups() else found.group(0)
        except IndexError:  # pragma: no cover - guarded by .groups()
            continue
        if not value:
            continue

        return Field[str](
            value=value,
            state=FieldState.PRESENT,
            confidence=pattern.confidence,
            confidence_method=ConfidenceMethod.DETERMINISTIC,
            evidence=(
                Evidence(
                    file_id=file_id,
                    file_path=file_path,
                    line_start=number,
                    line_end=number,
                    raw_line=line,
                    source_type=source_type,
                ),
            ),
            provenance=FieldProvenance(
                pack_id=pack.pack_id,
                pack_version=pack.pack_version,
                pattern_id=f"identity:{pattern.field}",
                source=PatternSource.BUILTIN,
            ),
        )

    return Field[str].unknown(
        UnknownReason.NO_MATCH,
        confidence_method=ConfidenceMethod.DETERMINISTIC,
    )


def extract_identity(
    pack: VendorPack | None,
    lines: list[str],
    *,
    file_id: str,
    file_path: str,
    source_type: SourceType = SourceType.CLI,
) -> DetectedDeviceIdentity:
    """Extract every identity field the pack knows how to find.

    A blank line cannot serve as evidence, so patterns that would match one are
    skipped rather than producing an uncitable claim.
    """
    if pack is None:
        return DetectedDeviceIdentity()

    extracted: dict[str, Field[str]] = {}
    citable = [line for line in lines]

    for name in IDENTITY_ORDER:
        patterns = pack.identities_for(name)
        if not patterns:
            continue

        # Every declared pattern for the field, first match wins. A platform can
        # write one fact more than one way -- JunOS writes `set system host-name`
        # in its flat form and an indented `host-name r1;` in its brace form --
        # and a pack covering both surfaces declares both. Consulting only the
        # first meant the second was read by nothing.
        #
        # Order is the pack's declaration order, so which surface is tried first
        # is a reviewable property of the file rather than an accident of
        # iteration.
        result: Field[str] | None = None
        for pattern in patterns:
            result = _apply(
                pattern,
                citable,
                file_id=file_id,
                file_path=file_path,
                source_type=source_type,
                pack=pack,
            )
            if result.state is FieldState.PRESENT:
                break
        assert result is not None  # narrowed by the emptiness check above
        extracted[name] = result

    return DetectedDeviceIdentity(**extracted)
