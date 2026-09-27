"""Describing a platform no pack knows, from one of its files (ADR 0067).

**The system proposes only what it can derive from the file.** It never proposes
a vendor or platform name: nothing in a configuration states whose it is in a
form this code could verify, and a name offered from a model's memory would be
an assertion about the input made from outside it. The administrator supplies
the name; the file supplies the structure.

What is derived, deterministically, with the evidence that produced it:

  * a syntax mode — XML parse, brace balance, the share of `set`-prefixed lines,
    indentation — reported as counts, never as a score;
  * a comment style, and a structural summary of plain facts;
  * candidate fingerprint lines — literal, anchored stems of column-zero lines
    that no active pack uses — ranked, for the administrator to choose from.

Every one of those is a proposal the administrator can change: the mode is a
choice with the derived one pre-selected, the fingerprints are unticked until
ticked, and a line of their own may replace them all. What is written is a stub
pack — detection and syntax, no patterns — through the lifecycle every pack uses
(`validate` -> `activate`). The training loop then runs unchanged.

Discarding a bootstrap removes every version of the platform from the trained
root and its activation-record entry, and returns its files to undetected.
"""

from __future__ import annotations

import re
import sqlite3
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import yaml

from api.audit.chain import AuditChain
from api.db import training as store
from api.ingest import format_detect, lines, redetect
from api.ingest.pack_activation import ActivationRecord
from api.ingest.packs import (
    PACKS_ROOT,
    TRAINED_ROOT,
    clear_pack_cache,
    discover_packs,
    load_active_packs,
    load_pack,
)
from api.ingest.validate import ValidationError, decode
from api.models.audit import Actor, Subject
from api.models.enums import ActorType, AuditAction, MatchType, PackStatus, SyntaxMode
from api.models.ingestion import DetectionOutcome, DetectionResult, FileFormat
from api.models.pack import DetectSignature, VendorPack
from api.parse.block_parser import IMPLEMENTED_MODES, build_tree
from api.train.activation import activate, validate
from api.train.errors import BootstrapError

FIRST_VERSION = "1.0.0"
MIN_FINGERPRINTS = 2
MAX_FINGERPRINTS = 5
MAX_CANDIDATES = 8
MAX_STEM_TOKENS = 3

SET_PATH_MAJORITY = 0.5
"""A file is read as flat `set` paths when at least half its lines start `set `.

A stated majority, not a tuned figure. Below it the `set` lines are commands
among others (RouterOS writes `set` under a section path), and the evidence line
says how many there were either way.
"""

COMMENT_PREFIXES: tuple[str, ...] = ("#", "!", "//", ";")
"""Line prefixes this module recognises as comment styles. Counted, never assumed."""

NAME = re.compile(r"^[a-z][a-z0-9-]{1,31}$")
"""Vendor and platform names: lower case, digits and hyphens. They become a
directory name and a pack id, so they are held to what is safe as both."""

ELIGIBLE_OUTCOMES = frozenset(
    {
        DetectionOutcome.NO_SIGNATURE_MATCHED,
        DetectionOutcome.BELOW_THRESHOLD,
        DetectionOutcome.NO_PACKS_AVAILABLE,
    }
)
"""A file no pack claims. AMBIGUOUS is excluded: two known packs competing for a
file is a signature problem between them, and a third pack would not resolve it."""

KEYWORD = re.compile(r"^[A-Za-z/][A-Za-z/_-]*$")
"""A stem token: letters, `/`, `_`, `-`. A digit, `=`, quote or address ends the
stem, because from there on the line carries a value, and a fingerprint that
quoted one device's values would detect only that device."""

PRINCIPLE = (
    "NIRIKSHAK proposes only what it can derive from this file: its structure, "
    "its comment style, and lines no known platform uses. It never proposes a "
    "vendor or platform name — nothing in the file states that in a form it can "
    "verify. You supply the name; the file supplies the structure."
)


# ---------------------------------------------------------------------------
# What the file shows
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SyntaxFinding:
    mode: SyntaxMode
    evidence: tuple[str, ...]

    @property
    def parseable(self) -> bool:
        return self.mode in IMPLEMENTED_MODES


@dataclass(frozen=True)
class CommentStyle:
    prefix: str | None
    counts: dict[str, int]


@dataclass(frozen=True)
class StructureSummary:
    total_lines: int
    blank_lines: int
    comment_lines: int
    content_lines: int
    indented_lines: int
    max_depth: int | None
    block_headers: tuple[str, ...]
    section_path_lines: int
    """Column-zero lines beginning `/` in a file with no indented line: if those
    open sections, no implemented mode scopes the lines after them."""


@dataclass(frozen=True)
class Fingerprint:
    stem: str
    pattern: str
    example: str
    line_number: int
    occurrences: int
    pasted: bool = False


@dataclass(frozen=True)
class Assessment:
    file_id: str
    filename: str
    eligible: bool
    reason: str
    detection_outcome: str
    detection_explanation: str
    file_format: str
    syntax: SyntaxFinding
    comments: CommentStyle
    structure: StructureSummary
    candidates: tuple[Fingerprint, ...]
    excluded_stems: int
    split_check: str
    principle: str = PRINCIPLE
    implemented_modes: tuple[str, ...] = field(
        default_factory=lambda: tuple(sorted(str(m) for m in IMPLEMENTED_MODES))
    )


def comment_style(physical: list[str]) -> CommentStyle:
    counts = {p: 0 for p in COMMENT_PREFIXES}
    for line in physical:
        stripped = line.strip()
        for prefix in COMMENT_PREFIXES:
            if stripped.startswith(prefix):
                counts[prefix] += 1
                break
    present = {p: n for p, n in counts.items() if n}
    if not present:
        return CommentStyle(prefix=None, counts={})
    best = max(present.items(), key=lambda item: (item[1], -COMMENT_PREFIXES.index(item[0])))
    return CommentStyle(prefix=best[0], counts=present)


def _content(physical: list[str], comment: str | None) -> list[str]:
    return [
        line
        for line in physical
        if line.strip() and not (comment and line.strip().startswith(comment))
    ]


def derive_syntax(text: str, physical: list[str], comment: str | None) -> SyntaxFinding:
    """The mode, and the counts that decided it. Rules apply in the order written."""
    claimed = format_detect.sniff(text)
    if claimed is FileFormat.XML:
        try:
            format_detect.detect(text)
        except ValidationError as exc:
            return SyntaxFinding(SyntaxMode.XML, (f"the file begins with '<' but {exc}",))
        return SyntaxFinding(SyntaxMode.XML, ("the file parses as XML",))
    if claimed is FileFormat.JSON:
        return SyntaxFinding(SyntaxMode.JSON, ("the file begins with '{' or '['",))

    content = _content(physical, comment)
    total = len(content)
    opens = sum(1 for line in content if line.rstrip().endswith("{"))
    closes = sum(1 for line in content if line.strip() in ("}", "};"))
    set_lines = sum(1 for line in content if line.lstrip().startswith("set "))
    indented = [line for line in content if line[:1] in (" ", "\t")]
    widths = sorted({len(line) - len(line.lstrip()) for line in indented})

    depth = lowest = 0
    for line in content:
        if line.rstrip().endswith("{"):
            depth += 1
        elif line.strip() in ("}", "};"):
            depth -= 1
            lowest = min(lowest, depth)
    balanced = opens > 0 and opens == closes and lowest >= 0

    counts = (
        f"{total} content lines; {opens} opening and {closes} closing braces; "
        f"{set_lines} lines begin 'set '; {len(indented)} lines indented"
        + (f" (widths {', '.join(str(w) for w in widths)})" if widths else "")
    )
    if balanced:
        return SyntaxFinding(SyntaxMode.BRACE, (f"{opens} balanced brace pairs", counts))
    evidence = [counts]
    if opens:
        evidence.append(f"braces are present but do not balance ({opens} open, {closes} close)")
    if total and set_lines / total >= SET_PATH_MAJORITY:
        evidence.insert(0, f"{set_lines} of {total} content lines begin 'set '")
        return SyntaxFinding(SyntaxMode.SET_PATH, tuple(evidence))
    if indented:
        evidence.insert(0, f"{len(indented)} of {total} content lines are indented")
    else:
        evidence.insert(0, "no line is indented: every statement is read at the top level")
    return SyntaxFinding(SyntaxMode.INDENT, tuple(evidence))


def structure_summary(
    text: str, physical: list[str], mode: SyntaxMode, comment: str | None
) -> StructureSummary:
    comments = sum(1 for line in physical if comment and line.strip().startswith(comment))
    blank = sum(1 for line in physical if not line.strip())
    content = _content(physical, comment)
    indented = sum(1 for line in content if line[:1] in (" ", "\t"))
    sections = sum(1 for line in content if line.startswith("/")) if not indented else 0

    max_depth: int | None = None
    headers: tuple[str, ...] = ()
    if mode in IMPLEMENTED_MODES:
        tree = build_tree(
            text,
            file_id="0" * 64,
            file_path="bootstrap",
            mode=mode,
            comment_prefixes=(comment,) if comment else (),
        )
        nodes = tree.in_source_order()
        max_depth = max((n.depth for n in nodes), default=0)
        seen: dict[str, None] = {}
        for node in nodes:
            if node.children:
                seen.setdefault(node.text, None)
        headers = tuple(seen)
    return StructureSummary(
        total_lines=len(physical),
        blank_lines=blank,
        comment_lines=comments,
        content_lines=len(content),
        indented_lines=indented,
        max_depth=max_depth,
        block_headers=headers,
        section_path_lines=sections,
    )


# ---------------------------------------------------------------------------
# Fingerprints
# ---------------------------------------------------------------------------


def stem_of(line: str) -> str:
    """The leading keywords of a line, up to the first value, at most three."""
    tokens: list[str] = []
    for token in line.split():
        if len(tokens) == MAX_STEM_TOKENS or not KEYWORD.match(token):
            break
        tokens.append(token)
    return " ".join(tokens)


REGEX_SPECIAL = frozenset(".^$*+?{}[]\\|()")


def _literal(text: str) -> str:
    """Escaped for a regex, escaping only what a regex would read as syntax.

    `re.escape` also escapes `-` and spaces, which is correct and unreadable: an
    administrator should not have to see through backslashes that change
    nothing to check what a fingerprint matches (DEVELOPER_GUIDE.md §4).
    """
    return "".join(f"\\{ch}" if ch in REGEX_SPECIAL else ch for ch in text)


def _pattern(stem: str, line: str) -> str:
    return f"^{_literal(stem)}$" if stem == line else f"^{_literal(stem)} "


def _known_elsewhere(packs: list[VendorPack]) -> tuple[list[re.Pattern[str]], set[str]]:
    signatures: list[re.Pattern[str]] = []
    examples: set[str] = set()
    for pack in packs:
        for sig in pack.detect:
            if str(sig.type) == MatchType.REGEX.value:
                try:
                    signatures.append(re.compile(sig.pattern))
                except re.error:  # pragma: no cover - a loaded pack's regexes compile
                    continue
        for pattern in pack.patterns:
            examples.update(e.strip() for e in pattern.examples)
        for identity in pack.identity:
            examples.update(e.strip() for e in identity.examples)
        for extraction in (pack.acl_extraction, pack.interface_extraction):
            if extraction is not None:
                examples.update(e.strip() for e in extraction.examples)
    return signatures, examples


def _used_elsewhere(
    stem: str, line: str, signatures: list[re.Pattern[str]], examples: set[str]
) -> bool:
    if any(sig.search(line) for sig in signatures):
        return True
    return any(e == stem or e.startswith(stem + " ") for e in examples)


def fingerprint_candidates(
    physical: list[str], packs: list[VendorPack], comment: str | None
) -> tuple[tuple[Fingerprint, ...], int]:
    """Ranked candidates, and how many stems were set aside as used elsewhere.

    Only column-zero lines are offered: detection matches raw lines, and an
    anchored stem from an indented line would match nothing. Ranking prefers
    longer stems — more literal words, more specific — then frequency, then the
    order the file gives.
    """
    signatures, examples = _known_elsewhere(packs)
    first: dict[str, tuple[int, str]] = {}
    count: Counter[str] = Counter()
    for number, line in enumerate(physical, start=1):
        if not line.strip() or line[:1] in (" ", "\t"):
            continue
        if comment and line.startswith(comment):
            continue
        stem = stem_of(line.rstrip())
        if not stem:
            continue
        count[stem] += 1
        first.setdefault(stem, (number, line.rstrip()))

    offered: list[Fingerprint] = []
    excluded = 0
    for stem, (number, line) in first.items():
        if _used_elsewhere(stem, line, signatures, examples):
            excluded += 1
            continue
        offered.append(
            Fingerprint(
                stem=stem,
                pattern=_pattern(stem, line),
                example=line,
                line_number=number,
                occurrences=count[stem],
            )
        )
    offered.sort(key=lambda f: (-len(f.stem.split()), -f.occurrences, f.line_number))
    return tuple(offered[:MAX_CANDIDATES]), excluded


def pasted_fingerprint(line: str, physical: list[str]) -> Fingerprint:
    """An administrator's own line. It must be a column-zero line of this file."""
    wanted = line.rstrip()
    for number, candidate in enumerate(physical, start=1):
        if candidate.rstrip() == wanted and wanted and candidate[:1] not in (" ", "\t"):
            return Fingerprint(
                stem=wanted,
                pattern=f"^{_literal(wanted)}$",
                example=wanted,
                line_number=number,
                occurrences=sum(1 for c in physical if c.rstrip() == wanted),
                pasted=True,
            )
    raise BootstrapError(
        f"{line!r} is not a line of this file at column zero. A fingerprint must be "
        "something the file actually says, where detection can see it.",
        conflict=False,
    )


# ---------------------------------------------------------------------------
# The corpus guard
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CorpusGuard:
    present: bool
    protected: dict[str, str]
    """sha256 -> split, for every evaluation and held-out file."""
    held_out_vendor: str | None

    def describe(self, file_id: str) -> str:
        if not self.present:
            return (
                "no corpus manifest in this deployment: there is no evaluation "
                "split to compare against"
            )
        if file_id in self.protected:
            return f"this file is in the {self.protected[file_id]} split"
        return "not an evaluation or held-out corpus file"


def corpus_guard(manifest: Path) -> CorpusGuard:
    if not manifest.is_file():
        return CorpusGuard(present=False, protected={}, held_out_vendor=None)
    raw = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
    protected = {
        str(entry["sha256"]): str(entry["split"])
        for entry in raw.get("files", [])
        if entry.get("split") in ("eval", "holdout") and entry.get("sha256")
    }
    return CorpusGuard(
        present=True, protected=protected, held_out_vendor=raw.get("held_out_vendor")
    )


# ---------------------------------------------------------------------------
# Assessment
# ---------------------------------------------------------------------------


def _stored_row(conn: sqlite3.Connection, file_id: str) -> sqlite3.Row | None:
    return conn.execute(
        """
        SELECT cf.file_id, cf.file_format, cf.detection_reason, cf.detected_vendor,
               (SELECT original_filename FROM ingestion WHERE file_id = cf.file_id
                 ORDER BY received_at LIMIT 1) AS filename
        FROM config_file cf WHERE cf.file_id = ?
        """,
        (file_id,),
    ).fetchone()


def _text(blob_root: Path, file_id: str) -> str:
    from api.ingest import blobs

    return decode(blobs.read(blob_root, file_id), min_printable=0.0).text


def assess(
    conn: sqlite3.Connection,
    file_id: str,
    *,
    blob_root: Path,
    packs: list[VendorPack],
    guard: CorpusGuard,
    min_score: float,
    min_margin: float,
) -> Assessment:
    row = _stored_row(conn, file_id)
    if row is None:
        raise KeyError(file_id)
    text = _text(blob_root, file_id)
    physical = lines.split_lines(text)
    comments = comment_style(physical)
    syntax = derive_syntax(text, physical, comments.prefix)
    summary = structure_summary(text, physical, syntax.mode, comments.prefix)
    candidates, excluded = fingerprint_candidates(physical, packs, comments.prefix)

    stored = redetect.stored_file(conn, blob_root, file_id)
    assert stored is not None
    detection = redetect.detect_stored(stored, packs, min_score=min_score, min_margin=min_margin)

    eligible, reason = True, "no pack claims this file"
    if file_id in guard.protected:
        eligible, reason = (
            False,
            (
                f"this file is in the corpus {guard.protected[file_id]} split. A platform "
                "described from it would be authored from the data it is measured on."
            ),
        )
    elif detection.outcome not in ELIGIBLE_OUTCOMES:
        eligible, reason = (
            False,
            (
                f"detection is {detection.outcome} ({detection.explain()}); bootstrap is "
                "for a file no known pack claims"
            ),
        )
    elif not syntax.parseable:
        eligible, reason = (
            False,
            (
                f"the file reads as {syntax.mode}, which the parser declares and does not "
                "implement; a pack for it would raise on every audit"
            ),
        )

    return Assessment(
        file_id=file_id,
        filename=row["filename"] or "",
        eligible=eligible,
        reason=reason,
        detection_outcome=str(detection.outcome),
        detection_explanation=detection.explain(),
        file_format=str(row["file_format"]),
        syntax=syntax,
        comments=comments,
        structure=summary,
        candidates=candidates,
        excluded_stems=excluded,
        split_check=guard.describe(file_id),
    )


# ---------------------------------------------------------------------------
# Writing the stub, and discarding it
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BootstrapRequest:
    file_id: str
    vendor: str
    os_family: str
    syntax_mode: SyntaxMode
    chosen_stems: tuple[str, ...] = ()
    pasted_lines: tuple[str, ...] = ()
    comment_prefixes: tuple[str, ...] | None = None


@dataclass(frozen=True)
class BootstrapResult:
    pack: VendorPack
    path: str
    detection: DetectionResult
    fingerprints: tuple[Fingerprint, ...]
    derived_mode: SyntaxMode
    also_matches: tuple[redetect.DetectionChange, ...]


def _check_names(vendor: str, os_family: str, guard: CorpusGuard) -> None:
    for label, value in (("vendor", vendor), ("platform", os_family)):
        if not NAME.match(value):
            raise BootstrapError(
                f"{label} {value!r} must be 2-32 characters of lower-case letters, "
                "digits and hyphens, starting with a letter: it becomes a pack id and "
                "a directory name",
                conflict=False,
            )
    if guard.held_out_vendor and vendor == guard.held_out_vendor:
        raise BootstrapError(
            f"{vendor!r} is the held-out vendor. Describing it would open the "
            "generalisation experiment's sealed data."
        )


def _existing(pack_id: str, roots: tuple[Path, ...]) -> list[VendorPack]:
    return [p for p in discover_packs(roots=roots) if p.pack_id == pack_id]


def create(
    conn: sqlite3.Connection,
    request: BootstrapRequest,
    *,
    admin: str,
    blob_root: Path,
    guard: CorpusGuard,
    min_score: float,
    min_margin: float,
    chain: AuditChain | None = None,
    trained_root: Path | None = None,
    builtin_root: Path | None = None,
) -> BootstrapResult:
    trained_root = trained_root if trained_root is not None else TRAINED_ROOT
    builtin_root = builtin_root if builtin_root is not None else PACKS_ROOT
    active = load_active_packs(use_cache=False)

    assessment = assess(
        conn,
        request.file_id,
        blob_root=blob_root,
        packs=active,
        guard=guard,
        min_score=min_score,
        min_margin=min_margin,
    )
    if not assessment.eligible:
        raise BootstrapError(assessment.reason)

    _check_names(request.vendor, request.os_family, guard)
    pack_id = f"{request.vendor}/{request.os_family}"
    if _existing(pack_id, (builtin_root, trained_root)):
        raise BootstrapError(
            f"{pack_id} already has a pack. Bootstrap describes a platform nobody has; "
            "extend an existing one through the training loop instead."
        )

    if request.syntax_mode not in IMPLEMENTED_MODES:
        raise BootstrapError(
            f"{request.syntax_mode} is declared and not implemented by the parser; "
            "a pack in that mode would raise on every audit",
            conflict=False,
        )

    physical = lines.split_lines(_text(blob_root, request.file_id))
    offered = {f.stem: f for f in assessment.candidates}
    chosen: list[Fingerprint] = []
    for stem in request.chosen_stems:
        if stem not in offered:
            raise BootstrapError(
                f"{stem!r} is not among the fingerprints derived from this file",
                conflict=False,
            )
        chosen.append(offered[stem])
    chosen.extend(pasted_fingerprint(line, physical) for line in request.pasted_lines)
    patterns = [f.pattern for f in chosen]
    if len(set(patterns)) != len(patterns):
        raise BootstrapError("the same fingerprint was chosen twice", conflict=False)
    if not MIN_FINGERPRINTS <= len(chosen) <= MAX_FINGERPRINTS:
        raise BootstrapError(
            f"choose {MIN_FINGERPRINTS}-{MAX_FINGERPRINTS} fingerprints; {len(chosen)} given",
            conflict=False,
        )

    # Equal weights summing to one: this file, which carries every fingerprint,
    # scores 1.0, and another file must carry most of them to reach the 0.60
    # threshold. Nothing is tuned to make detection pass.
    weight = round(1.0 / len(chosen), 6)
    comments = (
        request.comment_prefixes
        if request.comment_prefixes is not None
        else ((assessment.comments.prefix,) if assessment.comments.prefix else ())
    )
    stub = VendorPack(
        vendor=request.vendor,
        os_family=request.os_family,
        pack_version=FIRST_VERSION,
        status=PackStatus.DRAFT,
        created_by=admin,
        created_at=datetime.now(UTC),
        syntax_mode=request.syntax_mode,
        comment_prefixes=tuple(c for c in comments if c),
        detect=tuple(
            DetectSignature(type=MatchType.REGEX, pattern=p, weight=weight) for p in patterns
        ),
    )

    # Decide before writing anything: the stub must claim this file under the
    # unchanged threshold and margin, and must not move any file already
    # identified as another platform.
    proposed = [*active, stub]
    stored = redetect.stored_file(conn, blob_root, request.file_id)
    assert stored is not None
    trial = redetect.detect_stored(stored, proposed, min_score=min_score, min_margin=min_margin)
    if trial.outcome is not DetectionOutcome.DETECTED or trial.vendor != stub.vendor:
        raise BootstrapError(
            f"with these fingerprints the file would not be detected as {pack_id}: "
            f"{trial.explain()}. Nothing was written."
        )
    changes = redetect.preview(
        conn, blob_root, proposed, min_score=min_score, min_margin=min_margin
    )
    moved = [c for c in changes if c.before is not None]
    if moved:
        listed = "; ".join(
            f"{c.filename or c.file_id[:12]} ({c.before} -> {c.after})" for c in moved
        )
        raise BootstrapError(
            f"these fingerprints would change the platform of files already identified: "
            f"{listed}. Choose fingerprints those files do not carry. Nothing was written."
        )
    also = tuple(c for c in changes if c.before is None and c.file_id != request.file_id)

    result = activate(validate(stub), trained_root=trained_root, builtin_root=builtin_root)
    clear_pack_cache()
    detection = redetect.record(
        conn,
        blob_root,
        request.file_id,
        load_active_packs(use_cache=False),
        min_score=min_score,
        min_margin=min_margin,
    )

    written = load_pack(Path(result.path))
    if chain is not None:
        actor = Actor(type=ActorType.HUMAN, id=admin, role="admin")
        subject = Subject(kind="vendor_pack", id=f"{written.pack_id}@{written.pack_version}")
        chain.append(
            actor=actor,
            action=AuditAction.PACK_CREATED,
            subject=subject,
            payload={
                "pack_id": written.pack_id,
                "pack_version": written.pack_version,
                "parent_version": None,
                "status": str(PackStatus.DRAFT),
                "bootstrapped_from_file": request.file_id,
                "syntax_mode": str(request.syntax_mode),
                "syntax_mode_derived": str(assessment.syntax.mode),
                "syntax_mode_overridden": request.syntax_mode is not assessment.syntax.mode,
                "detect": patterns,
                "pasted_fingerprints": len(request.pasted_lines),
            },
        )
        chain.append(
            actor=actor,
            action=AuditAction.PACK_ACTIVATED,
            subject=subject,
            payload={
                "pack_id": written.pack_id,
                "pack_version": written.pack_version,
                "previous_version": None,
                "checksum": written.checksum,
                "pattern_count": 0,
            },
        )

    return BootstrapResult(
        pack=written,
        path=result.path,
        detection=detection,
        fingerprints=tuple(chosen),
        derived_mode=assessment.syntax.mode,
        also_matches=also,
    )


def bootstrapped_platform(
    conn: sqlite3.Connection,
    file_id: str,
    *,
    trained_root: Path | None = None,
    builtin_root: Path | None = None,
) -> str | None:
    """The platform this file is detected as, if it was bootstrapped (discardable)."""
    trained_root = trained_root if trained_root is not None else TRAINED_ROOT
    builtin_root = builtin_root if builtin_root is not None else PACKS_ROOT
    row = conn.execute(
        "SELECT detected_vendor, detected_os_family FROM config_file WHERE file_id = ?",
        (file_id,),
    ).fetchone()
    if row is None or not row["detected_vendor"]:
        return None
    pack_id = f"{row['detected_vendor']}/{row['detected_os_family']}"
    if _existing(pack_id, (builtin_root,)) or not _existing(pack_id, (trained_root,)):
        return None
    return pack_id


@dataclass(frozen=True)
class DiscardResult:
    pack_id: str
    versions_removed: tuple[str, ...]
    files_reset: tuple[str, ...]


def discard(
    conn: sqlite3.Connection,
    pack_id: str,
    *,
    admin: str,
    blob_root: Path,
    min_score: float,
    min_margin: float,
    chain: AuditChain | None = None,
    trained_root: Path | None = None,
    builtin_root: Path | None = None,
) -> DiscardResult:
    """Remove a bootstrapped platform entirely, and return its files to undetected."""
    trained_root = trained_root if trained_root is not None else TRAINED_ROOT
    builtin_root = builtin_root if builtin_root is not None else PACKS_ROOT

    if _existing(pack_id, (builtin_root,)):
        raise BootstrapError(
            f"{pack_id} ships with NIRIKSHAK; only a bootstrapped platform can be discarded"
        )
    files = sorted(
        path
        for path in trained_root.rglob("*.yaml")
        if path.name != "activation.yaml" and load_pack(path).pack_id == pack_id
    )
    if not files:
        raise KeyError(pack_id)

    vendor, os_family = pack_id.split("/", 1)
    affected = tuple(
        row["file_id"]
        for row in conn.execute(
            "SELECT file_id FROM config_file WHERE detected_vendor = ? AND detected_os_family = ?",
            (vendor, os_family),
        )
    )

    # The record entry goes first. With it gone and a file left behind, that file
    # is inert unless its own status is ACTIVE — so the deletions below are
    # undone by restoring the record if any of them fails, never left half-done.
    before = ActivationRecord.load(trained_root)
    before.without(pack_id).save(trained_root)
    try:
        for path in files:
            path.unlink()
    except OSError:
        before.save(trained_root)
        raise
    for directory in {path.parent for path in files}:
        if directory != trained_root and not any(directory.iterdir()):
            directory.rmdir()
    clear_pack_cache()

    remaining = load_active_packs(use_cache=False)
    for file_id in affected:
        store.clear_unknown_lines(conn, file_id)
        redetect.record(
            conn, blob_root, file_id, remaining, min_score=min_score, min_margin=min_margin
        )

    versions = tuple(sorted(p.stem for p in files))
    if chain is not None:
        chain.append(
            actor=Actor(type=ActorType.HUMAN, id=admin, role="admin"),
            action=AuditAction.PACK_ROLLED_BACK,
            subject=Subject(kind="vendor_pack", id=pack_id),
            payload={
                "pack_id": pack_id,
                "pack_version": None,
                "rolled_back_from": before.version_for(pack_id),
                "discarded": True,
                "versions_removed": list(versions),
                "files_reset": len(affected),
            },
        )
    return DiscardResult(pack_id=pack_id, versions_removed=versions, files_reset=affected)


__all__ = [
    "PRINCIPLE",
    "Assessment",
    "BootstrapRequest",
    "BootstrapResult",
    "CorpusGuard",
    "DiscardResult",
    "Fingerprint",
    "assess",
    "bootstrapped_platform",
    "comment_style",
    "corpus_guard",
    "create",
    "derive_syntax",
    "discard",
    "fingerprint_candidates",
    "pasted_fingerprint",
    "stem_of",
    "structure_summary",
]
