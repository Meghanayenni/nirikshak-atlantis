"""Deterministic, data-driven vendor fingerprinting.

No model, no heuristic guessing, no if-chain of vendor names. Detection reads
the `detect` signatures already defined by the `VendorPack` contract, scores
each candidate platform, and either identifies it or says UNKNOWN.

**Two thresholds, not one.** A single "highest score wins" rule fails in two
different ways that deserve different answers:

  * `min_score` catches **thin evidence** — a file that barely resembles
    anything we know.
  * `min_margin` catches **ambiguity** — a file that resembles Cisco IOS and
    Arista EOS equally, which is common because the syntaxes genuinely overlap.

Both produce UNKNOWN, but the recorded reason differs, and the second is the one
telling us the signature set needs a *discriminating* pattern rather than more
patterns. Collapsing them into one number would mean confidently picking the
winner of a coin flip.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from api.models.ingestion import (
    DetectionOutcome,
    DetectionResult,
    SignatureHit,
    VendorCandidate,
)
from api.models.pack import VendorPack


@dataclass(frozen=True)
class _Scored:
    vendor: str
    os_family: str
    score: float
    hits: tuple[SignatureHit, ...]


def _match_signature(
    pattern: str, kind: str, lines: list[str], filename: str
) -> tuple[int, str] | None:
    """Return the first (line_number, raw_line) a signature matches, if any."""
    if kind == "filename":
        return (0, filename) if re.search(pattern, filename) else None

    try:
        rx = re.compile(pattern, re.MULTILINE)
    except re.error:
        return None

    for number, line in enumerate(lines, start=1):
        if rx.search(line):
            return (number, line)
    return None


def score_pack(pack: VendorPack, lines: list[str], filename: str) -> _Scored:
    """Sum the weights of this pack's signatures that appear in the file."""
    total = 0.0
    hits: list[SignatureHit] = []

    for signature in pack.detect:
        kind = str(signature.type)
        found = _match_signature(signature.pattern, kind, lines, filename)
        if found is None:
            continue
        number, raw = found
        total += signature.weight
        hits.append(
            SignatureHit(
                pattern=signature.pattern,
                weight=signature.weight,
                line_number=number if number > 0 else None,
                raw_line=raw[:200],
            )
        )

    return _Scored(
        vendor=pack.vendor,
        os_family=pack.os_family,
        score=round(total, 6),
        hits=tuple(hits),
    )


def detect_vendor(
    packs: list[VendorPack],
    lines: list[str],
    *,
    filename: str = "",
    min_score: float,
    min_margin: float,
) -> DetectionResult:
    """Identify the platform, or abstain with a reason.

    The result always carries its candidates and their matching signatures, so
    both "why did you think this was Cisco?" and "why did you refuse to say?"
    are answerable from the record alone.
    """
    if not packs:
        return DetectionResult(
            outcome=DetectionOutcome.NO_PACKS_AVAILABLE,
            min_score=min_score,
            min_margin=min_margin,
        )

    scored = sorted(
        (score_pack(p, lines, filename) for p in packs),
        key=lambda s: (-s.score, s.vendor, s.os_family),
    )
    candidates = tuple(
        VendorCandidate(vendor=s.vendor, os_family=s.os_family, score=s.score, hits=s.hits)
        for s in scored
        if s.score > 0
    )

    if not candidates:
        return DetectionResult(
            outcome=DetectionOutcome.NO_SIGNATURE_MATCHED,
            candidates=(),
            min_score=min_score,
            min_margin=min_margin,
        )

    best = candidates[0]
    runner_up_score = candidates[1].score if len(candidates) > 1 else 0.0
    margin = round(best.score - runner_up_score, 6)

    if best.score < min_score:
        return DetectionResult(
            outcome=DetectionOutcome.BELOW_THRESHOLD,
            score=best.score,
            margin=margin,
            candidates=candidates,
            min_score=min_score,
            min_margin=min_margin,
        )

    if margin < min_margin:
        return DetectionResult(
            outcome=DetectionOutcome.AMBIGUOUS,
            score=best.score,
            margin=margin,
            candidates=candidates,
            min_score=min_score,
            min_margin=min_margin,
        )

    return DetectionResult(
        outcome=DetectionOutcome.DETECTED,
        vendor=best.vendor,
        os_family=best.os_family,
        score=best.score,
        margin=margin,
        candidates=candidates,
        min_score=min_score,
        min_margin=min_margin,
    )
