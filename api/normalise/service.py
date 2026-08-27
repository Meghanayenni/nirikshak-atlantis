"""Building the Canonical Security Model — the trust boundary itself.

Everything upstream of the object this module returns may deal in vendor syntax.
Nothing downstream of it may. The compliance engine at P6 accepts a CSM and
nothing else, so this is where a configuration stops being text and becomes a set
of typed claims each carrying its own justification.

What normalisation actually does is small, and deliberately so:

  * carries determined fields through **unchanged** — P5 never re-decides a
    fact P4 already established, and never adds confidence to one
  * resolves every absent field through `absence.py`, which is the phase's
    substance
  * flattens the detected identity into the canonical one
  * scrubs residue for the P10 queue
  * records which pack version actually applied

**One CSM per configuration file** (decision D14). The signature accepts a list
so a later fleet-grouping layer is a change of caller rather than a change of
contract, but P5 supports exactly one and says so by raising rather than by
inventing merge semantics for two.

What this module does *not* do:

  * decide whether any value is secure — that is P6, and it cannot import this
  * populate `acls` — the corpus contains no ACL at all, in any split, so ACL
    patterns could only be written from general vendor knowledge against zero
    evidence. See `docs/CORPUS_PREREQUISITES.md`.
  * populate `interfaces` — no pack declares interface patterns, and interfaces
    are structured objects rather than `Field`s, so the P4 machinery does not
    produce one. Deferred to the phase that consumes them.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from api.models.csm import CanonicalSecurityModel, CsmSource, DeviceIdentity
from api.models.enums import UnknownReason
from api.models.field import Field
from api.models.ingestion import DetectedDeviceIdentity
from api.models.pack import VendorPack
from api.models.parsing import ParseResult
from api.normalise.absence import resolve_absent_field
from api.normalise.errors import ConflictingSourcesError, MissingPackError
from api.normalise.identity import to_canonical_identity
from api.normalise.residue import to_unknown_lines


def build_csm(
    parse_result: ParseResult,
    pack: VendorPack,
    *,
    device_id: str,
    detected_identity: DetectedDeviceIdentity | None = None,
    ingested_at: datetime | None = None,
) -> CanonicalSecurityModel:
    """Normalise one parsed configuration into one canonical model."""
    return build_csm_from_sources(
        [parse_result],
        pack,
        device_id=device_id,
        detected_identity=detected_identity,
        ingested_at=ingested_at,
    )


def build_csm_from_sources(
    parse_results: list[ParseResult],
    pack: VendorPack,
    *,
    device_id: str,
    detected_identity: DetectedDeviceIdentity | None = None,
    ingested_at: datetime | None = None,
) -> CanonicalSecurityModel:
    """Normalise one device's parse results into one canonical model.

    Raises rather than merging when sources disagree. At P5 only the
    single-source path is supported (D14); the plural signature exists so the
    fleet layer that eventually groups files does not require this contract to
    change underneath it.
    """
    if pack is None:  # pragma: no cover - typed, but the failure is worth naming
        raise MissingPackError(
            "normalisation needs the pack that produced the parse: it carries the "
            "capability and default knowledge every absence rule runs on"
        )
    if not parse_results:
        raise MissingPackError("normalisation needs at least one parse result")

    fields = _merge_fields(parse_results)
    resolved = _resolve_absences(fields, pack)

    identity = _identity(
        detected_identity,
        device_id=device_id,
        pack=pack,
    )

    residue = tuple(
        line
        for result in parse_results
        for line in to_unknown_lines(result.residue, file_id=result.file_id)
    )

    return CanonicalSecurityModel(
        device=identity,
        source=CsmSource(
            file_ids=tuple(r.file_id for r in parse_results),
            ingested_at=ingested_at,
            # The version that ACTUALLY applied, taken from the parse result
            # rather than from whichever pack happens to be active now. A report
            # written later must say which pack read the line, not which pack
            # would read it today.
            pack_versions={
                r.vendor: r.pack_version for r in parse_results if r.vendor and r.pack_version
            },
        ),
        fields=resolved,
        acls=(),
        interfaces=(),
        residue=residue,
    )


def _merge_fields(parse_results: list[ParseResult]) -> dict[str, Field[Any]]:
    """Collect fields across sources, refusing to break a disagreement.

    With one source this is a copy. With several, two files claiming different
    values for the same control is a question for a human — picking one would be
    inventing an answer the configurations do not give, which is the same
    reasoning P4 applies to two conflicting lines within one file.
    """
    merged: dict[str, Field[Any]] = {}
    for result in parse_results:
        for name, field in result.fields.items():
            existing = merged.get(name)
            if existing is None:
                merged[name] = field
                continue
            if existing.value != field.value or existing.state is not field.state:
                raise ConflictingSourcesError(name, [existing.value, field.value])
    return merged


def _resolve_absences(
    fields: dict[str, Field[Any]],
    pack: VendorPack,
) -> dict[str, Field[Any]]:
    """Apply the absence table — but only to fields that are genuinely absent.

    A determined field is passed through by reference. `Field` is frozen, so
    "unchanged" is literal: the same object, with the same evidence tuple, and no
    opportunity for a citation to be dropped or a confidence to be adjusted on
    the way across the trust boundary.

    **Abstaining is not the same as being absent.** Only `NO_MATCH` means the
    directive is missing from this configuration; every other reason means the
    directive is *there* and something else went wrong. `CONFLICTING_EVIDENCE` is
    the case that matters: two lines disagree, so the control **is** configured —
    contradictorily. Running the absence table over it would assert the platform's
    documented default for a control the operator has explicitly set, mark it
    determinable so a rule could PASS on it, and discard the very citations that
    show the contradiction. Three failures at once, from one wrong branch.

    So anything not abstaining for `NO_MATCH` passes through untouched, keeping
    its reason and its evidence.
    """
    out: dict[str, Field[Any]] = {}
    for name, field in fields.items():
        if field.is_determinable or field.unknown_reason is not UnknownReason.NO_MATCH:
            out[name] = field
            continue
        out[name] = resolve_absent_field(name, pack)
    return out


def _identity(
    detected: DetectedDeviceIdentity | None,
    *,
    device_id: str,
    pack: VendorPack,
) -> DeviceIdentity:
    """Canonical identity, falling back to what the pack alone establishes.

    A file with no identity patterns still produces a valid model: the vendor and
    OS family are known from detection, and every other attribute is `None`
    rather than fabricated.
    """
    if detected is None:
        return DeviceIdentity(
            device_id=device_id,
            vendor=pack.vendor,
            os_family=pack.os_family,
        )
    return to_canonical_identity(
        detected,
        device_id=device_id,
        vendor=pack.vendor,
        os_family=pack.os_family,
    )
