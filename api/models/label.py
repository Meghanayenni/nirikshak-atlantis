"""Ground-truth labels — what a human read in the configuration (decision D31).

ADR 0010 states the rule this contract exists to make structural:

    A label is authored from the configuration, never from parser output.

Running the parser and accepting its answer as truth measures self-consistency
and nothing else. It is the easiest way to produce an evaluation that looks
excellent and is worthless, and it is easy to slide into by accident — so the
defence here is the shape of the type rather than the discipline of the author.

**Note what this contract does not have.** There is no `predicted_value`, no
`parser_said`, no `confidence`, no `state` copied from a `Field`. A label carries
what a person read and why they read it that way. There is nowhere for a
pipeline result to be written even if something tried.

## Three states, not two

`Determinability` is the distinction that makes correct abstention measurable.
A field the system declined to answer is only a success if the control genuinely
could not be determined from the file; if a human could read it straight off the
page, the same abstention is a **miss**. Collapsing the two turns missing parser
coverage into a success rate, which is the specific dishonesty the whole harness
exists to avoid.

No automated process can supply this judgement. That is why it is recorded, with
a rationale, by the person who made it.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, model_validator
from pydantic import Field as Constraint

from api.models.enums import Verdict

SHA256_HEX = r"^[0-9a-f]{64}$"


class Determinability(StrEnum):
    """Whether the control can be established from the configuration alone."""

    DETERMINABLE = "determinable"
    """A competent engineer reading only this file can state the value.

    Includes absence, but only for fields that exist by being configured — a
    banner, a list of logging hosts, a list of NTP servers. If the file has no
    `banner` directive then the device has no banner, and that is readable.
    """

    NOT_DETERMINABLE = "not_determinable"
    """The value depends on what the platform does when the directive is absent.

    An unset SSH version, an unmentioned HTTPS listener or an absent password
    policy are all questions about documented platform behaviour, not about this
    file. Abstaining on these is the correct answer, and scoring it as one is the
    point of the distinction.
    """


class ReviewStatus(StrEnum):
    """Whether a second person has checked the label against the file."""

    UNREVIEWED = "unreviewed"
    """Authored but not independently checked. May not be described as
    independent ground truth anywhere in a report."""

    REVIEWED = "reviewed"
    """A named reviewer read the configuration and agreed with the label."""


class FieldLabel(BaseModel):
    """The expected value of one canonical field on one configuration.

    `evidence_line` and `evidence_text` record the line the labeller read. They
    are verified against the file at load time, so a label that cites a line the
    file does not contain fails rather than scoring something.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    field: str = Constraint(min_length=1)
    determinability: Determinability

    expected_value: Any = None
    evidence_line: int | None = Constraint(default=None, ge=1)
    evidence_text: str | None = None

    rationale: str = Constraint(
        min_length=1,
        max_length=600,
        description="Why the labeller read the file this way. Their own words.",
    )

    @model_validator(mode="after")
    def _check(self) -> FieldLabel:
        if self.determinability is Determinability.NOT_DETERMINABLE:
            if self.expected_value is not None:
                raise ValueError(
                    f"{self.field!r} is labelled not determinable but carries an "
                    "expected value; if a value can be stated the field is determinable"
                )
            if self.evidence_line is not None or self.evidence_text is not None:
                raise ValueError(
                    f"{self.field!r} is labelled not determinable but cites a line; "
                    "a citation is a claim that the file establishes the value"
                )

        if (self.evidence_line is None) != (self.evidence_text is None):
            raise ValueError(
                f"{self.field!r} cites half an evidence pointer — a line number "
                "without its text cannot be checked against the file, and text "
                "without a line number cannot be located in it"
            )
        return self

    @property
    def is_determinable(self) -> bool:
        return self.determinability is Determinability.DETERMINABLE

    @property
    def cites_a_line(self) -> bool:
        """False for a value read from the ABSENCE of a directive.

        Absence is a legitimate reading, and it has no line to point at. The
        evidence-integrity metric excludes these rather than counting them as
        missing citations.
        """
        return self.evidence_line is not None


class VerdictLabel(BaseModel):
    """The verdict a human derived for one rule on one configuration.

    Derived by taking the labelled field value and applying the rule's condition
    **as written in the rule file** — not by running the engine, and not from the
    rule's rationale prose. Where the two disagree that is a rule defect worth
    recording separately; folding it in here would report a rule-authoring
    mistake as an engine error.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    rule_id: str = Constraint(min_length=1)
    expected_verdict: Verdict
    rationale: str = Constraint(min_length=1, max_length=600)


class LabelProvenance(BaseModel):
    """Who authored the label, when, and whether anyone has checked it.

    `pattern_author_conflict` is the mechanism decision D35 asks for. When the
    label author and the vendor pack author share an origin, correlated error is
    invisible: the labeller can encode the same misunderstanding into the ground
    truth that the pattern author encoded into the parser, and the measurement
    comes out clean while proving nothing.

    The flag does not fix that. It makes it **loud** instead of silent, so a
    report can separate the populations and a reader can discount accordingly.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    labelled_by: str = Constraint(
        min_length=1, description="Who read the configuration. Recorded honestly."
    )
    labelled_at: datetime
    authored_from: str = Constraint(
        min_length=1,
        description="The artefact the labeller read. Must be the raw configuration path.",
    )

    review_status: ReviewStatus = ReviewStatus.UNREVIEWED
    reviewed_by: str | None = None
    reviewed_at: datetime | None = None

    pattern_author_conflict: bool = Constraint(
        default=False,
        description="True when the labeller also authored patterns for this platform.",
    )
    conflict_note: str | None = None

    parser_state_at_labelling: str | None = Constraint(
        default=None,
        description=(
            "Pack version active when the label was written, or null when the field "
            "was labelled before any pattern for it existed (ADR 0010). Metadata "
            "about when, never a source of truth."
        ),
    )

    @model_validator(mode="after")
    def _check(self) -> LabelProvenance:
        if self.review_status is ReviewStatus.REVIEWED and not self.reviewed_by:
            raise ValueError(
                "a label cannot be marked reviewed without naming the reviewer; "
                "an anonymous review is not a review"
            )
        if self.review_status is ReviewStatus.UNREVIEWED and self.reviewed_by:
            raise ValueError("a reviewer is named but the label is not marked reviewed")

        if self.pattern_author_conflict and not self.conflict_note:
            raise ValueError(
                "a declared authorship conflict must explain itself — a reader "
                "discounting a number needs to know by how much and why"
            )
        return self

    @property
    def is_independent(self) -> bool:
        """Whether this label may be described as independent ground truth.

        Both conditions, deliberately. A reviewed label whose author wrote the
        patterns is still correlated until the reviewer is someone else, and an
        unreviewed label is nobody's checked work regardless of who wrote it.
        """
        return self.review_status is ReviewStatus.REVIEWED and not self.pattern_author_conflict


class FileLabels(BaseModel):
    """Every label for one configuration file.

    `file_sha256` binds the labels to the exact bytes they were written against.
    A configuration edited after labelling would otherwise be scored against
    ground truth describing a file that no longer exists — silently, and in the
    flattering direction as often as not.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    corpus_path: str = Constraint(min_length=1, description="Relative to corpus/")
    split: str = Constraint(min_length=1)
    vendor: str = Constraint(min_length=1)
    os_family: str = Constraint(min_length=1)
    file_sha256: str = Constraint(pattern=SHA256_HEX)

    provenance: LabelProvenance
    fields: tuple[FieldLabel, ...] = Constraint(min_length=1)
    verdicts: tuple[VerdictLabel, ...] = ()

    @model_validator(mode="after")
    def _check(self) -> FileLabels:
        seen_fields: set[str] = set()
        for label in self.fields:
            if label.field in seen_fields:
                raise ValueError(f"duplicate label for field {label.field!r}")
            seen_fields.add(label.field)

        seen_rules: set[str] = set()
        for verdict in self.verdicts:
            if verdict.rule_id in seen_rules:
                raise ValueError(f"duplicate label for rule {verdict.rule_id!r}")
            seen_rules.add(verdict.rule_id)

        if self.split != "eval":
            raise ValueError(
                f"{self.corpus_path!r} is in the {self.split!r} split. Only evaluation "
                "files are labelled: labelling a development file would put ground "
                "truth where patterns are authored, and the held-out vendor may not "
                "be read at all"
            )
        return self

    @property
    def determinable(self) -> tuple[FieldLabel, ...]:
        return tuple(f for f in self.fields if f.is_determinable)

    @property
    def not_determinable(self) -> tuple[FieldLabel, ...]:
        return tuple(f for f in self.fields if not f.is_determinable)
