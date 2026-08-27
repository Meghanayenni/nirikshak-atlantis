"""NIRIKSHAK data contracts.

The eleven contracts, defined before any logic that uses them (DEVELOPER_GUIDE.md §14).
Everything the system claims is expressed in these types, and the guarantees
that matter are enforced by their validators rather than by the code that
happens to call them:

  * A PRESENT field without evidence cannot be constructed        (Rule 2)
  * Sub-threshold confidence becomes UNKNOWN at construction      (Rule 3)
  * Uncalibrated similarity cannot support any claim              (R7)
  * A PASS/FAIL finding without justification cannot be built     (Rule 2)
  * A snippet without a vetter cannot be built                    (Rule 4)
  * An audit record whose hash disagrees with its payload raises
  * A rule carrying framework prose is rejected by extra="forbid" (R16)

`FieldMatch` and `ParseResult` (P4) sit alongside the eleven rather than among
them: they are the parse layer's own carriers, not claims the whole system is
built on. They live here because `api/models/` is the one package every layer
may import, which is what keeps the parser from having to be imported to read
what it produced.
"""

from api.models.acl import (
    ACL,
    AclApplication,
    ACLEntry,
    AclEntryFlags,
    AddrSpec,
    PortSpec,
    ProtocolSpec,
)
from api.models.audit import (
    GENESIS_HASH,
    Actor,
    AuditRecord,
    Subject,
    canonical_json,
    hash_payload,
)
from api.models.config_tree import ConfigNode, ConfigTree, UnplacedLine
from api.models.csm import (
    CANONICAL_FIELD_NAMES,
    CSM_VERSION,
    CanonicalSecurityModel,
    CsmSource,
    DeviceIdentity,
    Interface,
    InterfaceAcl,
    UnknownLine,
)
from api.models.enums import (
    AbsenceAction,
    AclAction,
    AclType,
    ActorType,
    AddrKind,
    AuditAction,
    CastType,
    ConditionOp,
    ConfidenceMethod,
    Direction,
    ExampleSource,
    FieldState,
    Framework,
    LockoutRisk,
    MappingProvenance,
    MatchType,
    PackStatus,
    PatternSource,
    PlatformSourceType,
    PortOp,
    ProvenanceStatus,
    Severity,
    SourceType,
    SyntaxMode,
    TrainingOutcome,
    UnknownReason,
    Verdict,
)
from api.models.evidence import Evidence, sha256_hex
from api.models.field import (
    Field,
    FieldProvenance,
    abstention_threshold,
    platform_default_confidence,
    platform_default_floor,
)
from api.models.finding import (
    Finding,
    FindingProvenance,
    ObservedValue,
    RemediationRef,
)
from api.models.pack import (
    IDENTITY_FIELDS,
    CaptureSpec,
    DetectSignature,
    IdentityPattern,
    LiteralBlock,
    MatchSpec,
    PatternDef,
    PatternProvenance,
    PatternScope,
    PlatformCapability,
    PlatformDefault,
    PlatformProvenance,
    VendorPack,
)
from api.models.parsing import FieldMatch, ParseResult
from api.models.rule import (
    MAX_RATIONALE_CHARS,
    AbsencePolicy,
    AppliesTo,
    CheckSpec,
    ComplianceRule,
    Condition,
    FrameworkRef,
)
from api.models.snippet import ImpactAssessment, RemediationSnippet
from api.models.training import Suggestion, TrainingExample

__all__ = [
    # evidence
    "Evidence",
    "sha256_hex",
    # config tree (R4)
    "ConfigNode",
    "ConfigTree",
    "UnplacedLine",
    # field (R7)
    "Field",
    "FieldProvenance",
    "abstention_threshold",
    "platform_default_confidence",
    "platform_default_floor",
    # acl
    "ACL",
    "ACLEntry",
    "AclApplication",
    "AclEntryFlags",
    "AddrSpec",
    "PortSpec",
    "ProtocolSpec",
    # csm
    "CanonicalSecurityModel",
    "CsmSource",
    "DeviceIdentity",
    "Interface",
    "InterfaceAcl",
    "UnknownLine",
    "CANONICAL_FIELD_NAMES",
    "CSM_VERSION",
    # pack
    "VendorPack",
    "PatternDef",
    "MatchSpec",
    "CaptureSpec",
    "PatternScope",
    "PatternProvenance",
    "DetectSignature",
    "IdentityPattern",
    "LiteralBlock",
    "IDENTITY_FIELDS",
    "PlatformDefault",
    "PlatformCapability",
    "PlatformProvenance",
    # parsing (P4)
    "FieldMatch",
    "ParseResult",
    # rule
    "ComplianceRule",
    "CheckSpec",
    "Condition",
    "AbsencePolicy",
    "AppliesTo",
    "FrameworkRef",
    "MAX_RATIONALE_CHARS",
    # finding
    "Finding",
    "FindingProvenance",
    "ObservedValue",
    "RemediationRef",
    # snippet
    "RemediationSnippet",
    "ImpactAssessment",
    # training
    "TrainingExample",
    "Suggestion",
    # audit
    "AuditRecord",
    "Actor",
    "Subject",
    "canonical_json",
    "hash_payload",
    "GENESIS_HASH",
    # enums
    "AbsenceAction",
    "AclAction",
    "AclType",
    "ActorType",
    "AddrKind",
    "AuditAction",
    "CastType",
    "ConditionOp",
    "ConfidenceMethod",
    "Direction",
    "ExampleSource",
    "FieldState",
    "Framework",
    "LockoutRisk",
    "MappingProvenance",
    "MatchType",
    "PackStatus",
    "PatternSource",
    "PlatformSourceType",
    "ProvenanceStatus",
    "PortOp",
    "Severity",
    "SourceType",
    "SyntaxMode",
    "TrainingOutcome",
    "UnknownReason",
    "Verdict",
]
