"""Closed vocabularies shared by every NIRIKSHAK contract.

Every enum here is a `StrEnum`, so values serialise as plain strings in YAML,
JSON and SQLite while remaining type-checked in Python.
"""

from enum import StrEnum

# ---------------------------------------------------------------------------
# Field state and confidence — DEVELOPER_GUIDE.md Rules 2 and 3, decision R7
# ---------------------------------------------------------------------------


class FieldState(StrEnum):
    """Why a canonical field holds the value it holds.

    Collapsing these four into a nullable value is what makes other tools
    produce misleading audits: `absent because the platform defaults to secure`
    and `absent because someone removed it` are opposite conclusions from
    identical evidence.
    """

    PRESENT = "present"
    """Observed in the configuration. Requires evidence."""

    ABSENT_DEFAULT = "absent_default"
    """Not configured; the documented platform default applies. Requires a citation."""

    ABSENT_UNSUPPORTED = "absent_unsupported"
    """The platform cannot express this control at all."""

    UNKNOWN = "unknown"
    """Undeterminable. Never a guess, never coerced into PASS or FAIL."""


class ConfidenceMethod(StrEnum):
    """How a field's confidence value was arrived at (decision R7).

    This is the discriminator between confidence *populations*. Populations are
    not comparable: a deterministic pattern match and a model similarity score
    are different kinds of claim that happen to share a numeric range.
    Calibration applies to exactly one of them.
    """

    DETERMINISTIC = "deterministic"
    """A vendor-pack pattern matched.

    Expresses confidence in the parser and the pattern. It is **not** an ML
    probability and must never be pooled with model-derived scores when fitting
    or reporting calibration.
    """

    ADMIN_CONFIRMED = "admin_confirmed"
    """A human ratified this mapping. Trust originates here, not from a score."""

    PLATFORM_DEFAULT = "platform_default"
    """Taken from the per-OS capability/default model. Carries its citation."""

    CALIBRATED_SIMILARITY = "calibrated_similarity"
    """Model-derived, mapped through a calibrator fitted on labelled ground truth.

    The only population whose confidence may be read as an approximate
    probability, and the only one the abstention threshold is tuned against.
    """

    UNCALIBRATED_SIMILARITY = "uncalibrated_similarity"
    """Model-derived, with no calibration fitted for this population yet.

    A raw similarity score is not a confidence. A field carrying this method is
    forced to UNKNOWN regardless of its numeric value — the score may be
    recorded and shown to an administrator, but it can never support a claim.
    """

    @property
    def is_model_derived(self) -> bool:
        """True when the value originated from an embedding similarity search."""
        return self in (
            ConfidenceMethod.CALIBRATED_SIMILARITY,
            ConfidenceMethod.UNCALIBRATED_SIMILARITY,
        )

    @property
    def is_probability(self) -> bool:
        """True only when the confidence may be interpreted as a probability.

        Used by the evaluation harness to select the population it calibrates
        and reports reliability for. Deterministic confidence is deliberately
        excluded (R7).
        """
        return self is ConfidenceMethod.CALIBRATED_SIMILARITY


class UnknownReason(StrEnum):
    """Why a field or finding abstained. Mandatory whenever state is UNKNOWN."""

    NO_MATCH = "no_match"
    LOW_CONFIDENCE = "low_confidence"
    UNCALIBRATED_CONFIDENCE = "uncalibrated_confidence"
    CAPABILITY_UNKNOWN = "capability_unknown"
    CONFLICTING_EVIDENCE = "conflicting_evidence"
    UNPARSED_BLOCK = "unparsed_block"
    NO_EVIDENCE = "no_evidence"

    RULE_TYPE_MISMATCH = "rule_type_mismatch"
    """A rule's operand could not be compared with the field's value (D18).

    A rule declaring `lte: "600"` against an integer field, or `contains` against
    a boolean. Its own reason rather than `no_match`, because the two say
    opposite things about where the fault lies: `no_match` means the vendor packs
    cannot read this control and it belongs in the training queue, while this
    means the packs read it fine and the *rule* is wrong. Collapsing them would
    hide a broken rule inside a legitimate abstention, where it would abstain on
    every device forever while looking like a coverage gap.
    """


# ---------------------------------------------------------------------------
# Sources and structure
# ---------------------------------------------------------------------------


class SourceType(StrEnum):
    """The shape of the artefact a piece of evidence came from."""

    CLI = "cli"
    XML = "xml"
    JSON = "json"


class SyntaxMode(StrEnum):
    """How a configuration file expresses hierarchy (decision R4)."""

    INDENT = "indent"
    """Significant leading whitespace — Cisco IOS, NX-OS, Arista EOS."""

    BRACE = "brace"
    """Curly-brace nesting — JunOS curly form, F5."""

    SET_PATH = "set_path"
    """Flat `set a b c value` paths — JunOS set form, PAN-OS set form."""

    XML = "xml"
    """Delegated to lxml; block_path derives from element ancestry."""

    JSON = "json"
    """Delegated to stdlib json; block_path derives from key ancestry."""


# ---------------------------------------------------------------------------
# Compliance
# ---------------------------------------------------------------------------


class Verdict(StrEnum):
    """The only outcomes the deterministic engine may produce (DEVELOPER_GUIDE.md §6)."""

    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ConditionOp(StrEnum):
    """Operators available to a declarative rule condition.

    Deliberately a closed set rather than arbitrary expressions, so a rule can
    never become a place where vendor logic or a model call reappears.
    """

    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"
    IN = "in"
    NOT_IN = "not_in"
    CONTAINS = "contains"
    IS_TRUE = "is_true"
    IS_FALSE = "is_false"
    NON_EMPTY = "non_empty"


class AbsenceAction(StrEnum):
    """What the engine does when a field is not PRESENT (absence-aware evaluation)."""

    EVALUATE = "evaluate"
    """Apply the platform's documented default and evaluate normally."""

    PASS = "pass"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"

    UNKNOWN = "unknown"
    """Abstain. The correct answer when platform support is undocumented."""


class Framework(StrEnum):
    CIS = "cis"
    NIST = "nist"
    STIG = "stig"
    ISO = "iso"


class MappingProvenance(StrEnum):
    """Whether a control mapping follows a published crosswalk (decision R16)."""

    OFFICIAL = "official"
    PROJECT_ASSERTED = "project_asserted"


# ---------------------------------------------------------------------------
# Platform knowledge provenance (decision D11)
# ---------------------------------------------------------------------------


class PlatformSourceType(StrEnum):
    """What kind of material backs a platform default or capability claim.

    A platform default is a security claim about a device made *without* a line
    of its configuration to cite — the whole point is that the line is absent.
    The citation is therefore the only justification the claim has, which is why
    it is typed rather than left as free text someone can fill with a hunch.
    """

    VENDOR_DOCUMENTATION = "vendor_documentation"
    """A vendor's own configuration guide, command reference or hardening guide."""

    VENDOR_RELEASE_NOTES = "vendor_release_notes"
    """Release notes or a security advisory, where a default changed at a version."""

    STANDARDS_BODY = "standards_body"
    """A published benchmark or standard stating the platform's behaviour."""

    PROJECT_ASSERTED = "project_asserted"
    """NIRIKSHAK's own claim, backed by no external source.

    Representable so that an assertion can be recorded honestly and reviewed
    later — **not** admissible. It is not vendor documentation, must never be
    presented as externally verified, and cannot support a compliance verdict
    (decision D11). A field resting on one abstains.
    """


class ProvenanceStatus(StrEnum):
    """Whether a platform claim's source has actually been obtained and read."""

    SOURCED = "sourced"
    """The named document was obtained and the locator points into it."""

    PROJECT_ASSERTED = "project_asserted"
    """Our own assertion. Recorded, visible, and not admissible (D11)."""

    @property
    def is_admissible(self) -> bool:
        """Whether a claim with this status may support a compliance verdict.

        Only `SOURCED`. An assertion we made ourselves is a note for a future
        reviewer, not evidence — treating it as evidence is how an unverified
        default becomes a PASS, which Rule 3 forbids outright.
        """
        return self is ProvenanceStatus.SOURCED


# ---------------------------------------------------------------------------
# ACL
# ---------------------------------------------------------------------------


class AclAction(StrEnum):
    PERMIT = "permit"
    DENY = "deny"


class AclType(StrEnum):
    STANDARD = "standard"
    EXTENDED = "extended"
    ZONE = "zone"
    SECURITY_GROUP = "security_group"


class Direction(StrEnum):
    IN = "in"
    OUT = "out"


class AddrKind(StrEnum):
    ANY = "any"
    HOST = "host"
    CIDR = "cidr"
    RANGE = "range"
    OBJECT = "object"


class PortOp(StrEnum):
    ANY = "any"
    EQ = "eq"
    RANGE = "range"
    LT = "lt"
    GT = "gt"
    NEQ = "neq"


# ---------------------------------------------------------------------------
# Vendor packs
# ---------------------------------------------------------------------------


class PackStatus(StrEnum):
    DRAFT = "draft"
    VALIDATED = "validated"
    ACTIVE = "active"
    DEPRECATED = "deprecated"


class PatternSource(StrEnum):
    BUILTIN = "builtin"
    ADMIN_TRAINED = "admin_trained"


class MatchType(StrEnum):
    """The five parse primitives (decision R4 added `block`)."""

    REGEX = "regex"
    TEXTFSM = "textfsm"
    XPATH = "xpath"
    JSONPATH = "jsonpath"
    BLOCK = "block"


class CastType(StrEnum):
    INT = "int"
    BOOL = "bool"
    STR = "str"
    LIST = "list"
    CIDR = "cidr"
    DURATION = "duration"


# ---------------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------------


class LockoutRisk(StrEnum):
    """Risk that applying a snippet strands the operator outside their own device."""

    NONE = "none"
    LOW = "low"
    HIGH = "high"


# ---------------------------------------------------------------------------
# Training and audit
# ---------------------------------------------------------------------------


class TrainingOutcome(StrEnum):
    """What the administrator actually did with the suggestions shown."""

    ACCEPTED_RANK_1 = "accepted_rank_1"
    ACCEPTED_RANK_2 = "accepted_rank_2"
    ACCEPTED_RANK_3 = "accepted_rank_3"
    CORRECTED = "corrected"
    REJECTED_NOT_SECURITY_RELEVANT = "rejected_not_security_relevant"

    @property
    def accepted_rank(self) -> int | None:
        """The 1-based rank accepted, or None if corrected or rejected."""
        mapping = {
            TrainingOutcome.ACCEPTED_RANK_1: 1,
            TrainingOutcome.ACCEPTED_RANK_2: 2,
            TrainingOutcome.ACCEPTED_RANK_3: 3,
        }
        return mapping.get(self)


class ExampleSource(StrEnum):
    SEED = "seed"
    ADMIN = "admin"


class ActorType(StrEnum):
    HUMAN = "human"
    SYSTEM = "system"
    MODEL = "model"


class AuditAction(StrEnum):
    FILE_INGESTED = "file_ingested"
    FILE_REJECTED = "file_rejected"
    """An upload was refused — binary, malformed, oversized or empty.

    Separate from FILE_INGESTED on purpose (decision D5): recording a refusal
    as an ingestion would misdescribe what happened, and an attempted upload of
    an unreadable file is itself worth keeping.
    """
    AUDIT_RUN = "audit_run"
    AI_SUGGESTED = "ai_suggested"
    ADMIN_CONFIRMED = "admin_confirmed"
    ADMIN_CORRECTED = "admin_corrected"
    PACK_CREATED = "pack_created"
    PACK_ACTIVATED = "pack_activated"
    PACK_ROLLED_BACK = "pack_rolled_back"
    REPORT_GENERATED = "report_generated"
