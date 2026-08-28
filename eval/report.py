"""Rendering the evaluation report.

The report's job is to make the numbers hard to over-read. Three habits carry
that, and each is a rule the renderer follows rather than a convention:

**Every rate prints its denominator.** A precision of 1.00 over eleven
observations and over eleven thousand are different claims, and a figure printed
alone invites the reader to assume the second.

**Populations are never merged.** Vendors with a parsing pack and detection-only
vendors appear in separate rows and no combined figure is computed anywhere
(decision D34). A pooled recall number would be dominated by "no pack was
written", which is a coverage statement wearing an accuracy statement's clothes.

**Absent measurements say why they are absent.** A metric that could not be
computed renders as `not exercised` or `deferred to P10`, never as a blank or a
zero. A zero is a measurement; these are not.

The corpus caveat is generated from the manifest rather than typed, so the day a
real sanitised configuration is added the wording changes on its own.
"""

from __future__ import annotations

from datetime import UTC, datetime

from api.models.enums import Verdict
from eval.corpus import corpus_is_synthetic, held_out_vendor, load_manifest
from eval.labels import load_labels
from eval.metrics import (
    FieldMetrics,
    by_field,
    by_vendor,
    detection_metrics,
    field_metrics,
    verdict_metrics,
    verdicts_by_vendor,
)
from eval.score import ScoreRun

WIDTH = 78


def _rate(value: float | None, denominator: int) -> str:
    """A rate with its denominator, or an honest dash."""
    if value is None or denominator == 0:
        return "     n/a"
    return f"{value:6.1%} /{denominator:>3d}"


def _rule(char: str = "-") -> str:
    return char * WIDTH


def _heading(text: str) -> list[str]:
    return ["", text.upper(), _rule("=")]


def render(run: ScoreRun) -> str:
    """The evaluation report, as plain text.

    Plain text rather than HTML: this is a measurement record meant to be read in
    a terminal, diffed between runs and pasted into a decision record. The
    operator-facing document with the visual design is the P8 compliance report,
    which is a different artefact for a different reader.
    """
    lines: list[str] = []
    labels = load_labels()
    manifest = load_manifest()
    synthetic = corpus_is_synthetic()

    lines += [
        _rule("="),
        "NIRIKSHAK — EVALUATION REPORT (P9)",
        _rule("="),
        "",
        "Accuracy is reported as a measurement, not a claim.",
        "",
        f"Generated      : {datetime.now(UTC).isoformat()}",
        f"Rulepack       : {run.rulepack_version}",
        f"Vendor packs   : {', '.join(f'{k} {v}' for k, v in run.pack_versions.items()) or 'none'}",
        f"Files scored   : {len(run.files_scored)} (evaluation split only)",
        f"Held-out vendor: {held_out_vendor()} — NOT READ (deferred to P10)",
    ]

    # ---------------------------------------------------------------- corpus
    lines += _heading("1. What this was measured on")
    if synthetic:
        lines += [
            "EVERY configuration in this corpus is SYNTHETIC — written by the team to",
            "be realistic, not captured from a real network. These are synthetic-corpus",
            "results. They are NOT real-world accuracy and may not be presented as such.",
            "",
            "A synthetic file contains exactly the shapes its author thought to include,",
            "so the parser is scored against its author's imagination rather than against",
            "the field.",
        ]
    else:  # pragma: no cover - no real configuration has been sourced
        lines += ["Some configurations are real and sanitised; see the manifest for provenance."]

    lines += ["", f"{'file':38s} {'split':7s} {'vendor':9s} labelled"]
    lines += [_rule()]
    for entry in manifest:
        mark = "yes" if entry.labelled else "no"
        note = "  (SEALED — not read)" if entry.is_sealed else ""
        lines.append(f"{entry.path:38s} {entry.split:7s} {entry.vendor:9s} {mark}{note}")

    # ------------------------------------------------------------ provenance
    lines += _heading("2. Ground-truth provenance")
    lines += [
        "A label is authored from the configuration, never from parser output.",
        "",
        f"{'file':38s} {'labelled by':22s} {'review':11s} conflict",
        _rule(),
    ]
    for label in labels:
        provenance = label.provenance
        conflict = "PATTERN AUTHOR" if provenance.pattern_author_conflict else "none"
        lines.append(
            f"{label.corpus_path:38s} {provenance.labelled_by:22s} "
            f"{provenance.review_status.value:11s} {conflict}"
        )

    independent = [label for label in labels if label.provenance.is_independent]
    lines += [
        "",
        f"Independently reviewed labels: {len(independent)} of {len(labels)}.",
    ]
    if len(independent) < len(labels):
        lines += [
            "",
            "NOT INDEPENDENT GROUND TRUTH. No label here has been reviewed by a second",
            "person, and the Cisco labels were written by the author of the Cisco parsing",
            "patterns. Correlated error between parser and ground truth is therefore not",
            "visible in the Cisco numbers: a field misunderstood while writing the pattern",
            "would be misunderstood the same way while writing the label.",
            "",
            "Arista and Juniper carry no such conflict — no parsing pattern has ever been",
            "written for either platform.",
        ]

    # -------------------------------------------------------------- detection
    lines += _heading("3. Vendor detection")
    detection = detection_metrics(run.detections)
    lines += [
        f"Correct   : {detection.correct} / {detection.total}",
        f"Wrong     : {detection.wrong}",
        f"Abstained : {detection.abstained}"
        + (f"  {detection.reasons}" if detection.reasons else ""),
        "",
        "Measured against the vendor the manifest records, which the author noted when",
        "writing the file and which no parser produced.",
    ]

    # ----------------------------------------------------------------- fields
    lines += _heading("4. Field extraction, by vendor")
    lines += [
        "Vendors with a parsing pack and detection-only vendors are NEVER pooled.",
        "A combined recall figure would be dominated by packs nobody has written.",
        "",
        f"{'vendor':10s} {'pack':6s} {'n':>4s} {'ok':>4s} {'wrong':>6s} {'miss':>5s} {'abst':>5s}"
        f" {'precision':>12s} {'recall':>12s}",
        _rule(),
    ]
    per_vendor: dict[str, FieldMetrics] = {}
    for vendor, observations in by_vendor(run.fields).items():
        metrics = field_metrics(observations, vendor)
        per_vendor[vendor] = metrics
        has_pack = "yes" if observations[0].has_parsing_pack else "NO"
        recall_n = metrics.correct + metrics.miss + metrics.wrong_confident
        lines.append(
            f"{vendor:10s} {has_pack:6s} {metrics.total:>4d} {metrics.correct:>4d} "
            f"{metrics.wrong_confident:>6d} {metrics.miss:>5d} {metrics.correct_abstention:>5d} "
            f"{_rate(metrics.precision, metrics.asserted):>12s} "
            f"{_rate(metrics.recall, recall_n):>12s}"
        )

    lines += [
        "",
        "ok    = determinable, and the system asserted the labelled value",
        "wrong = the system asserted a value the label contradicts",
        "miss  = determinable, and the system abstained  (a recall loss)",
        "abst  = not determinable, and the system abstained  (honest uncertainty)",
        "",
        "Rates print as percentage / denominator. A rate over a handful of observations",
        "is not a characterisation of a parser.",
    ]

    # ------------------------------------------------------- safety metrics
    lines += _heading("5. Abstention and the wrong-confident rate")
    lines += [
        f"{'vendor':10s} {'wrong-confident':>18s} {'correct-abstention':>21s}",
        _rule(),
    ]
    for vendor, metrics in per_vendor.items():
        lines.append(
            f"{vendor:10s} {_rate(metrics.wrong_confident_rate, metrics.asserted):>18s} "
            f"{_rate(metrics.correct_abstention_rate, metrics.abstained):>21s}"
        )

    total_wrong = sum(m.wrong_confident for m in per_vendor.values())
    total_asserted = sum(m.asserted for m in per_vendor.values())
    lines += [
        "",
        f"Wrong-confident answers across all vendors: {total_wrong} "
        f"of {total_asserted} assertions.",
    ]
    if total_wrong == 0:
        lines += [
            "",
            "A zero here is NOT evidence of accuracy. The system asserts a value only",
            "where a deterministic pattern matched, and it currently holds patterns for",
            "one platform. A system that asserts little cannot assert much wrongly.",
            "Read this figure alongside the miss counts above, not instead of them.",
        ]

    # ------------------------------------------------------ evidence integrity
    lines += _heading("6. Evidence integrity")
    lines += [
        "Rule 2 — a correct value carrying a citation that does not support it is a",
        "failure, not a rounding error. Scored separately from value accuracy.",
        "",
        f"{'vendor':10s} {'checked':>8s} {'correct':>8s} {'wrong line':>11s} {'missing':>8s}"
        f" {'integrity':>12s}",
        _rule(),
    ]
    for vendor, metrics in per_vendor.items():
        lines.append(
            f"{vendor:10s} {metrics.evidence_scored:>8d} {metrics.evidence_correct:>8d} "
            f"{metrics.evidence_wrong_line:>11d} {metrics.evidence_missing:>8d} "
            f"{_rate(metrics.evidence_integrity, metrics.evidence_scored):>12s}"
        )
    lines += [
        "",
        "Scored only where a citation can be checked: the system asserted a value AND",
        "the labeller read it off a specific line. A label resting on the ABSENCE of a",
        "directive has no line to point at and is excluded rather than counted as a",
        "missing citation.",
    ]

    # ------------------------------------------------------------ per field
    lines += _heading("7. Field extraction, by canonical field")
    lines += [
        f"{'field':24s} {'n':>3s} {'ok':>3s} {'wrong':>6s} {'miss':>5s} {'abst':>5s}",
        _rule(),
    ]
    for name, observations in by_field(run.fields).items():
        metrics = field_metrics(observations, name)
        lines.append(
            f"{name:24s} {metrics.total:>3d} {metrics.correct:>3d} "
            f"{metrics.wrong_confident:>6d} {metrics.miss:>5d} {metrics.correct_abstention:>5d}"
        )

    # ------------------------------------------------------------- verdicts
    lines += _heading("8. Compliance verdicts")
    classes = [Verdict.PASS, Verdict.FAIL, Verdict.UNKNOWN, Verdict.NOT_APPLICABLE]

    for vendor, observations in verdicts_by_vendor(run.verdicts).items():
        metrics = verdict_metrics(observations, vendor)
        lines += ["", f"{vendor} — {metrics.total} verdicts", _rule()]
        corner = "expected vs actual"
        header = f"{corner:22s}" + "".join(f"{c.value:>16s}" for c in classes)
        lines.append(header)
        for expected in classes:
            row = f"{expected.value:22s}" + "".join(
                f"{metrics.count(expected, actual):>16d}" for actual in classes
            )
            lines.append(row)

        lines.append("")
        for verdict in classes:
            if not metrics.exercised(verdict):
                lines.append(f"  {verdict.value:16s} not exercised — no label expects this class")
                continue
            lines.append(
                f"  {verdict.value:16s} precision "
                f"{_rate(metrics.precision(verdict), metrics.actual_total(verdict))}"
                f"   recall {_rate(metrics.recall(verdict), metrics.expected_total(verdict))}"
            )

    lines += [
        "",
        "Expected verdicts were derived by a human applying each rule's condition AS",
        "WRITTEN to the labelled field value — never by running the engine. Where a",
        "rule's condition and its own rationale disagree, that is a rule defect and is",
        "recorded in ADR 0016, not folded into this matrix.",
    ]

    # -------------------------------------------------------- absence branches
    lines += _heading("9. Absence-aware evaluation — branch coverage")
    lines += [
        "Reported as branch coverage rather than as an accuracy percentage. Zero",
        "platform defaults have been sourced, so every absent field takes one branch",
        "and an accuracy figure over it would be measuring a constant.",
        "",
        f"{'field state':26s} {'count':>8s}",
        _rule(),
    ]
    for state, count in run.absence_branches.items():
        lines.append(f"{state:26s} {count:>8d}")
    if "absent_default" not in run.absence_branches:
        lines += [
            "",
            "absent_default             0  — the AbsenceAction.EVALUATE branch has never",
            "                                fired on real data. It cannot until vendor",
            "                                documentation is sourced (SOURCING_BACKLOG 2).",
        ]
    lines += [
        "",
        "Counted over platforms that produce canonical fields at all. Detection-only",
        "platforms produce none, so they contribute nothing to this table rather than",
        "contributing zeros.",
    ]

    # ------------------------------------------------------------- deferred
    lines += _heading("10. Not measured, and why")
    lines += [
        "held-out generalisation  deferred to P10 — the metric is defined over the",
        "                         similarity layer, and api/learn/ is empty. The PAN-OS",
        "                         holdout was not opened at any point during this run.",
        "",
        "top-3 mapping accuracy   deferred to P10 — same reason.",
        "",
        "calibration              not possible — every field carries DETERMINISTIC",
        "                         confidence at a constant 1.00, which R7 forbids reading",
        "                         as a probability. There is one population and nothing",
        "                         to calibrate until the model arrives.",
        "",
        "ACL analysis accuracy    not measured — the corpus contains no access list.",
        "",
        "framework coverage       not measured — every rule ships frameworks: [].",
        "",
        "remediation coverage     not measured — the vetted snippet library is empty.",
    ]

    # ------------------------------------------------------------- caveats
    lines += _heading("11. What this report does not claim")
    lines += [
        "  * Real-world accuracy of any kind. The corpus is synthetic.",
        "  * Broad or universal vendor coverage. Three vendors, one with a parsing pack.",
        "  * A parser accuracy figure that generalises beyond these files.",
        "  * Absence-aware evaluation accuracy — the branch never fires.",
        "  * Calibrated confidence, or that the abstention threshold is tuned.",
        "  * Generalisation to the held-out vendor.",
        "  * That its labels are independent ground truth — they are unreviewed, and",
        "    for Cisco they share an author with the patterns being scored.",
        "",
        _rule("="),
    ]

    return "\n".join(lines) + "\n"
