"""Contracts for the ingestion layer.

Ingestion answers three questions and no others: what file is this, what
platform is it, and what are its lines. It does not parse security fields, does
not build a canonical model, and does not decide anything.

The types here follow the same rule as the rest of NIRIKSHAK: an answer the
system is not entitled to give is UNKNOWN, and it says why.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, model_validator
from pydantic import Field as Constraint

from api.models.enums import SourceType
from api.models.field import Field


class FileFormat(StrEnum):
    """The shape of an ingested artefact."""

    CLI = "cli"
    XML = "xml"
    JSON = "json"

    def to_source_type(self) -> SourceType:
        return {
            FileFormat.CLI: SourceType.CLI,
            FileFormat.XML: SourceType.XML,
            FileFormat.JSON: SourceType.JSON,
        }[self]


class RejectionReason(StrEnum):
    """Why a file was refused. Machine-readable, so the UI can group them."""

    EMPTY = "empty"
    TOO_LARGE = "too_large"
    BINARY_CONTENT = "binary_content"
    UNDECODABLE = "undecodable"
    MALFORMED_XML = "malformed_xml"
    MALFORMED_JSON = "malformed_json"
    ARCHIVE_TOO_MANY_ENTRIES = "archive_too_many_entries"
    ARCHIVE_TOO_LARGE = "archive_too_large"
    ARCHIVE_COMPRESSION_BOMB = "archive_compression_bomb"
    ARCHIVE_UNSAFE_PATH = "archive_unsafe_path"
    BATCH_LIMIT_EXCEEDED = "batch_limit_exceeded"


class DetectionOutcome(StrEnum):
    """Whether the platform was identified, and if not, why not.

    The two abstention reasons are kept apart deliberately. `BELOW_THRESHOLD`
    says the evidence was thin; `AMBIGUOUS` says two platforms were too close to
    separate. They call for different fixes — more signatures versus a
    *discriminating* signature — so collapsing them would hide the useful half.
    """

    DETECTED = "detected"
    NO_SIGNATURE_MATCHED = "no_signature_matched"
    BELOW_THRESHOLD = "below_threshold"
    AMBIGUOUS = "ambiguous"
    NO_PACKS_AVAILABLE = "no_packs_available"

    @property
    def is_known(self) -> bool:
        return self is DetectionOutcome.DETECTED


class IngestionStatus(StrEnum):
    INGESTED = "ingested"
    DUPLICATE = "duplicate"
    REJECTED = "rejected"


class SignatureHit(BaseModel):
    """One detection signature that matched, and where.

    Detection carries evidence for the same reason a finding does: "why did you
    think this was Cisco?" must be answerable, and so must "why did you refuse
    to say?".
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    pattern: str = Constraint(min_length=1)
    weight: float = Constraint(ge=0.0, le=1.0)
    line_number: int | None = Constraint(default=None, ge=1)
    raw_line: str | None = None


class VendorCandidate(BaseModel):
    """One platform's score against a file."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    vendor: str
    os_family: str
    score: float = Constraint(ge=0.0)
    hits: tuple[SignatureHit, ...] = ()

    @property
    def label(self) -> str:
        return f"{self.vendor}/{self.os_family}"


class DetectionResult(BaseModel):
    """The outcome of deterministic vendor fingerprinting.

    `vendor` and `os_family` are populated only when `outcome` is DETECTED. An
    ambiguous or thin result leaves them None rather than recording the
    best guess, because a guessed platform would silently select the wrong
    parsing rules for every line that follows.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    outcome: DetectionOutcome
    vendor: str | None = None
    os_family: str | None = None

    score: float | None = Constraint(default=None, ge=0.0)
    margin: float | None = Constraint(default=None, ge=0.0)
    candidates: tuple[VendorCandidate, ...] = ()

    min_score: float = Constraint(ge=0.0, le=1.0)
    min_margin: float = Constraint(ge=0.0, le=1.0)

    @model_validator(mode="after")
    def _check(self) -> DetectionResult:
        if self.outcome is DetectionOutcome.DETECTED:
            if not self.vendor or not self.os_family:
                raise ValueError("a DETECTED result must name the platform")
            if self.score is None:
                raise ValueError(
                    "a DETECTED result must carry the score that justified it — "
                    "a platform without its evidence is a guess"
                )
        elif self.vendor is not None or self.os_family is not None:
            raise ValueError(
                f"outcome {self.outcome} must not name a vendor; an unidentified "
                "platform stays UNKNOWN rather than becoming the best guess"
            )
        return self

    @property
    def is_known(self) -> bool:
        return self.outcome.is_known

    @property
    def label(self) -> str:
        return f"{self.vendor}/{self.os_family}" if self.is_known else "UNKNOWN"

    def explain(self) -> str:
        """A sentence an operator can act on."""
        if self.outcome is DetectionOutcome.DETECTED:
            return f"{self.label} (score {self.score:.2f}, margin {self.margin:.2f})"
        if self.outcome is DetectionOutcome.AMBIGUOUS:
            names = ", ".join(c.label for c in self.candidates[:2])
            return (
                f"UNKNOWN — {names} scored too close to separate "
                f"(margin {self.margin:.2f} < {self.min_margin:.2f})"
            )
        if self.outcome is DetectionOutcome.BELOW_THRESHOLD:
            best = self.candidates[0].label if self.candidates else "nothing"
            return (
                f"UNKNOWN — best candidate {best} scored {self.score:.2f}, "
                f"below the {self.min_score:.2f} threshold"
            )
        if self.outcome is DetectionOutcome.NO_PACKS_AVAILABLE:
            return "UNKNOWN — no detection packs are loaded"
        return "UNKNOWN — no signature matched"


class DetectedDeviceIdentity(BaseModel):
    """What the configuration says about the device it belongs to.

    Every field is a `Field[str]`, so each carries its own evidence and abstains
    independently: a file with a hostname but no serial yields one PRESENT and
    one UNKNOWN, never a fabricated serial.

    **Not** `api.models.csm.DeviceIdentity`, which is the canonical model's
    resolved identity — flat strings, plus a `device_id`. Both types were called
    `DeviceIdentity` until P5, and only the CSM one was exported from
    `api.models`, so `from api.models import DeviceIdentity` silently returned
    the wrong class for anyone meaning this one. P5 is the first layer that
    converts between them, which is exactly where that would have bitten, so the
    ingestion side took the more specific name.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    hostname: Field[str] | None = None
    model: Field[str] | None = None
    os_version: Field[str] | None = None
    serial: Field[str] | None = None
    domain_name: Field[str] | None = None

    def known_fields(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for name in ("hostname", "model", "os_version", "serial", "domain_name"):
            field: Field[str] | None = getattr(self, name)
            if field is not None and field.is_determinable and field.value:
                out[name] = field.value
        return out

    @property
    def display_name(self) -> str:
        known = self.known_fields()
        return known.get("hostname", "unidentified device")


class LineRecord(BaseModel):
    """One physical line, exactly as it appeared."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    line_number: int = Constraint(ge=1)
    text: str
    line_sha256: str = Constraint(pattern=r"^[0-9a-f]{64}$")


class IngestedFile(BaseModel):
    """A file that was accepted, with everything ingestion determined about it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    file_id: str = Constraint(pattern=r"^[0-9a-f]{64}$", description="sha256 of raw bytes")
    original_filename: str = Constraint(min_length=1)
    size_bytes: int = Constraint(ge=0)
    line_count: int = Constraint(ge=0)
    encoding: str = Constraint(min_length=1)
    file_format: FileFormat

    detection: DetectionResult
    identity: DetectedDeviceIdentity = Constraint(default_factory=DetectedDeviceIdentity)

    blob_path: str = Constraint(min_length=1)
    ingested_at: datetime | None = None
    duplicate_of_existing: bool = False

    @property
    def status(self) -> IngestionStatus:
        return IngestionStatus.DUPLICATE if self.duplicate_of_existing else IngestionStatus.INGESTED

    def audit_payload(self) -> dict[str, object]:
        """What enters the hash chain — identifiers and hashes, never content.

        Note what is absent: no line, no fragment, no sample. The audit database
        records that a file was ingested and what it was, not what was in it.
        """
        return {
            "file_id": self.file_id,
            "filename": self.original_filename,
            "sha256": self.file_id,
            "size_bytes": self.size_bytes,
            "line_count": self.line_count,
            "encoding": self.encoding,
            "file_format": str(self.file_format),
            "detected_vendor": self.detection.vendor,
            "detected_os_family": self.detection.os_family,
            "detection_outcome": str(self.detection.outcome),
            "detection_score": self.detection.score,
            "duplicate": self.duplicate_of_existing,
        }


class IngestionRejection(BaseModel):
    """A file that was refused, and why.

    A refusal is a first-class outcome: one unreadable file in fifty must not
    cost the operator the other forty-nine.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    original_filename: str = Constraint(min_length=1)
    reason: RejectionReason
    detail: str = Constraint(min_length=1, description="A sentence for the operator")
    size_bytes: int | None = Constraint(default=None, ge=0)
    sha256: str | None = None

    @property
    def status(self) -> IngestionStatus:
        return IngestionStatus.REJECTED

    def audit_payload(self) -> dict[str, object]:
        return {
            "filename": self.original_filename,
            "reason": str(self.reason),
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
        }


class IngestionBatch(BaseModel):
    """The result of one upload, file by file."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    batch_id: str = Constraint(min_length=1)
    accepted: tuple[IngestedFile, ...] = ()
    rejected: tuple[IngestionRejection, ...] = ()

    @property
    def total(self) -> int:
        return len(self.accepted) + len(self.rejected)

    @property
    def identified(self) -> int:
        return sum(1 for f in self.accepted if f.detection.is_known)

    @property
    def unidentified(self) -> int:
        return sum(1 for f in self.accepted if not f.detection.is_known)

    def summary(self) -> str:
        return (
            f"{self.total} file(s): {len(self.accepted)} accepted "
            f"({self.identified} identified, {self.unidentified} UNKNOWN vendor), "
            f"{len(self.rejected)} rejected"
        )
