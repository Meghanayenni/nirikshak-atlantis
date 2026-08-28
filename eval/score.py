"""Running the pipeline over the evaluation split and comparing it to ground truth.

This is the one module in the harness that may reach the pipeline, and the
direction is strictly one-way: it reads labels that were produced without any
pipeline involvement, runs the system, and compares. Nothing here writes a label,
and `eval/labels.py` cannot import what this module imports.

**Only the evaluation split is scored.** `dev` is refused even though the parser
handles those files best — scoring the configurations patterns were authored
from measures memorisation. `holdout` is refused before a file handle is opened.

## What "the system asserted a value" means

A canonical field is an assertion when its state is PRESENT or ABSENT_DEFAULT:
both are claims about the device. UNKNOWN and a field the model never produced
are abstentions. ABSENT_UNSUPPORTED is a claim that the platform cannot express
the control, which is also an assertion — though no pack currently produces one,
since that requires sourced capability data.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from api.comply.engine import evaluate_device
from api.comply.rulepacks import load_rulepack
from api.config import settings
from api.ingest.packs import find_pack, load_active_packs
from api.ingest.vendor_detect import detect_vendor
from api.models.enums import FieldState, Verdict
from api.models.label import FileLabels
from api.normalise.service import build_csm
from api.parse.service import parse_configuration
from eval.corpus import CorpusEntry, find_entry, read_configuration, scoreable_entries
from eval.errors import ScoringError
from eval.labels import labels_by_path
from eval.metrics import (
    DetectionObservation,
    EvidenceOutcome,
    FieldObservation,
    FieldOutcome,
    VerdictObservation,
)

ASSERTED_STATES = frozenset(
    {FieldState.PRESENT, FieldState.ABSENT_DEFAULT, FieldState.ABSENT_UNSUPPORTED}
)
"""States that constitute a claim about the device.

`ABSENT_DEFAULT` is included deliberately. A value inferred from a documented
platform default is still an assertion the operator will act on, and exempting
it would let the system make unfalsifiable claims by routing them through the
absence engine.
"""


@dataclass(frozen=True)
class ScoreRun:
    """Everything one evaluation run produced."""

    fields: list[FieldObservation]
    verdicts: list[VerdictObservation]
    detections: list[DetectionObservation]
    absence_branches: dict[str, int]
    files_scored: tuple[str, ...]
    rulepack_version: str
    pack_versions: dict[str, str]


def _values_equal(expected: object, actual: object) -> bool:
    """Compare a labelled value with a parsed one.

    Lists are compared as ordered sequences after normalising tuples, because
    `logging_hosts` arrives as a list from YAML and may be either from the
    canonical model. Nothing else is coerced: a string "2" is not the integer 2,
    and treating them as equal would hide a genuine cast defect.
    """
    if isinstance(expected, list | tuple) or isinstance(actual, list | tuple):
        if not isinstance(expected, list | tuple) or not isinstance(actual, list | tuple):
            return False
        return list(expected) == list(actual)
    return bool(expected == actual) and type(expected) is type(actual)


def score_file(entry: CorpusEntry, labels: FileLabels) -> ScoreRun:
    """Score one evaluation configuration against its ground truth."""
    if not entry.is_scoreable:
        raise ScoringError(
            f"refusing to score {entry.path!r}: it is in the {entry.split!r} split. "
            "Only evaluation files may be scored — scoring development files "
            "measures memorisation."
        )

    text = read_configuration(entry)
    file_id = hashlib.sha256(text.encode("utf-8")).hexdigest()
    packs = load_active_packs(use_cache=False)

    detection = detect_vendor(
        packs,
        text.splitlines(),
        filename=entry.path.rsplit("/", 1)[-1],
        min_score=settings.detection_min_score,
        min_margin=settings.detection_min_margin,
    )
    detections = [
        DetectionObservation(
            corpus_path=entry.path,
            expected_vendor=entry.vendor,
            detected_vendor=detection.vendor,
            outcome_reason=detection.outcome.value,
        )
    ]

    pack = find_pack(entry.vendor, entry.os_family, packs)
    if pack is None:
        raise ScoringError(f"no pack for {entry.vendor}/{entry.os_family}")

    parsed = parse_configuration(text, pack, file_id=file_id, file_path=entry.path)
    csm = build_csm(parsed, pack, device_id=file_id)
    has_pack = bool(pack.patterns)

    # -- fields ------------------------------------------------------------
    observations: list[FieldObservation] = []
    for label in labels.fields:
        parsed_field = csm.fields.get(label.field)
        asserted = parsed_field is not None and parsed_field.state in ASSERTED_STATES
        system_value = parsed_field.value if asserted and parsed_field else None
        cited_line = (
            parsed_field.evidence[0].line_start
            if asserted and parsed_field and parsed_field.evidence
            else None
        )

        if asserted:
            correct_value = label.is_determinable and _values_equal(
                label.expected_value, system_value
            )
            outcome = FieldOutcome.CORRECT if correct_value else FieldOutcome.WRONG_CONFIDENT
        else:
            outcome = (
                FieldOutcome.MISS if label.is_determinable else FieldOutcome.CORRECT_ABSTENTION
            )

        # Evidence integrity, scored only where a citation can be checked: the
        # system asserted something and the labeller read it off a specific line.
        if not asserted or not label.cites_a_line:
            evidence = EvidenceOutcome.NOT_SCORED
        elif cited_line is None:
            evidence = EvidenceOutcome.MISSING
        elif cited_line == label.evidence_line:
            evidence = EvidenceOutcome.CORRECT
        else:
            evidence = EvidenceOutcome.WRONG_LINE

        observations.append(
            FieldObservation(
                corpus_path=entry.path,
                vendor=entry.vendor,
                os_family=entry.os_family,
                field=label.field,
                determinable=label.is_determinable,
                expected_value=label.expected_value,
                system_asserted=asserted,
                system_value=system_value,
                outcome=outcome,
                evidence=evidence,
                labelled_line=label.evidence_line,
                cited_line=cited_line,
                has_parsing_pack=has_pack,
                pattern_author_conflict=labels.provenance.pattern_author_conflict,
            )
        )

    # -- verdicts ----------------------------------------------------------
    rulepack = load_rulepack()
    findings = evaluate_device(csm, rulepack, audit_id=f"eval-{file_id[:12]}")
    by_rule = {f.rule_id: f for f in findings}

    verdicts = [
        VerdictObservation(
            corpus_path=entry.path,
            vendor=entry.vendor,
            rule_id=label.rule_id,
            expected=label.expected_verdict,
            actual=by_rule[label.rule_id].status
            if label.rule_id in by_rule
            else Verdict.NOT_APPLICABLE,
            has_parsing_pack=has_pack,
        )
        for label in labels.verdicts
    ]

    # -- absence branch coverage ------------------------------------------
    branches: dict[str, int] = {}
    for parsed_field in csm.fields.values():
        if parsed_field.state is not FieldState.PRESENT:
            branches[parsed_field.state.value] = branches.get(parsed_field.state.value, 0) + 1

    return ScoreRun(
        fields=observations,
        verdicts=verdicts,
        detections=detections,
        absence_branches=branches,
        files_scored=(entry.path,),
        rulepack_version=rulepack.version,
        pack_versions={pack.pack_id: pack.pack_version},
    )


def score_all() -> ScoreRun:
    """Score every labelled evaluation file. The harness entry point.

    A labelled file the manifest does not mark scoreable is an error rather than
    a skip: it means the manifest and the labels disagree about which split a
    file is in, and silently scoring neither would hide that.
    """
    labels = labels_by_path()
    entries = scoreable_entries()

    fields: list[FieldObservation] = []
    verdicts: list[VerdictObservation] = []
    detections: list[DetectionObservation] = []
    branches: dict[str, int] = {}
    scored: list[str] = []
    packs: dict[str, str] = {}
    rulepack_version = ""

    for entry in entries:
        if entry.path not in labels:
            continue
        run = score_file(entry, labels[entry.path])
        fields += run.fields
        verdicts += run.verdicts
        detections += run.detections
        for name, count in run.absence_branches.items():
            branches[name] = branches.get(name, 0) + count
        scored += list(run.files_scored)
        packs.update(run.pack_versions)
        rulepack_version = run.rulepack_version

    for path in labels:
        if find_entry(path).split != "eval":
            raise ScoringError(f"{path!r} is labelled but is not in the evaluation split")

    return ScoreRun(
        fields=fields,
        verdicts=verdicts,
        detections=detections,
        absence_branches=dict(sorted(branches.items())),
        files_scored=tuple(sorted(scored)),
        rulepack_version=rulepack_version,
        pack_versions=dict(sorted(packs.items())),
    )
