"""Turning one confirmed line into one vendor-pack pattern.

This is the module DEVELOPER_GUIDE.md §4 is about, and the rule it states is a constraint
on *style*, not only on correctness:

> Generated patterns must be predictable and boring: tokenise the confirmed line,
> replace the captured token with `(\\S+)`, escape the rest, anchor with `^`, show
> it to the administrator, allow editing before activation.
>
> Do not generate clever regexes. A pattern an administrator cannot read is one
> they cannot verify.

So the compiler here is deliberately unambitious. It does not infer alternation,
it does not detect optional tokens, it does not merge two confirmations into one
general pattern, and it never guesses which token carries the value — the
administrator says which one, because they are the only party who knows whether
`2` in `ip ssh version 2` is the value or part of the command name.

**Nothing enters a pattern that a human did not confirm.** `compile_pattern`
takes a `TrainingExample` — a recorded decision with a named `confirmed_by` — and
refuses a bare `Suggestion`. That refusal is the learning loop's entire safety
argument in one function signature.

**Scope defaults to the literal header** (ADR 0011). A line confirmed inside
`line vty 0 4` compiles to a scope matching that block and no other. Generalising
to a numeric range is an explicit opt-in the administrator makes and sees,
because loose scoping is how a console timeout ends up reported as a management
idle timeout (decision D9).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from api.models.csm import CANONICAL_FIELD_NAMES
from api.models.enums import CastType, MatchType, PatternSource, TrainingOutcome
from api.models.pack import CaptureSpec, MatchSpec, PatternDef, PatternProvenance, PatternScope
from api.models.training import TrainingExample
from api.train.errors import NotConfirmedError, PatternCompileError, PatternRejectedError

CAPTURE = r"(\S+)"
"""The one capture form.

`(\\S+)` is what DEVELOPER_GUIDE.md §4 names. Widening it to `(.+)` or narrowing it to
`(\\d+)` per field would make the generated pattern depend on a judgement the
administrator was never asked to make.
"""

TOKEN_GAP = r"\s+"
"""Tokens are joined by "one or more spaces" rather than by the exact run of
whitespace observed. Configuration exports vary in alignment, and a pattern that
broke on two spaces instead of one would be a mis-parse arriving dressed as an
absent directive."""

MAX_TOKENS = 24
"""Matches `api/learn/signature.py`. A forty-token line is not a command being
confirmed; it is prose, a certificate body, or a mis-detected literal block."""

UNSAFE_CONSTRUCTS: tuple[tuple[str, str], ...] = (
    (r"\.\*", "`.*` matches anything, which is not a pattern but the absence of one"),
    (r"\.\+", "`.+` matches anything non-empty; name the tokens instead"),
    (r"\([^)]*[*+][^)]*\)\s*[*+]", "a nested quantifier can take exponential time to fail"),
)
"""Constructs refused in a hand-edited pattern (D51).

Not a general ReDoS analysis, and not offered as one. These are the shapes that
turn a boring pattern into an unreadable or a slow one, and refusing them keeps
the promise that an administrator can read what they activated.
"""


@dataclass(frozen=True)
class CompileRequest:
    """What the administrator decided, beyond which field the line means.

    `value_token` is an index into the line's whitespace-separated tokens. `None`
    means the line's *presence* is the fact — `no ip http server` has nothing to
    capture — and `literal_value` then supplies what the field becomes, exactly
    as the hand-written packs express negation forms.
    """

    value_token: int | None = None
    literal_value: str | None = None
    cast: CastType = CastType.STR
    block_path: tuple[str, ...] = ()
    generalise_numeric_scope: bool = False
    """D9 — an explicit opt-in the administrator sees, never an assumption."""


def tokenise(line: str) -> list[str]:
    """Whitespace-separated tokens of a confirmed line.

    Patterns match `node.text`, which the parser has already stripped of
    indentation, so leading whitespace is structure rather than content and does
    not appear here.
    """
    return line.split()


def build_regex(line: str, value_token: int | None) -> str:
    """The pattern itself: escape everything, capture one token, anchor both ends.

    Anchored at the end as well as the start. The engine matches with `re.match`,
    so without a closing anchor a pattern for `ip ssh version 2` would also fire
    on `ip ssh version 2 extra` — which the hand-written Cisco pack lists as a
    negative example precisely because it is a different statement.
    """
    tokens = tokenise(line)
    if not tokens:
        raise PatternCompileError("cannot compile a pattern from a blank line")
    if len(tokens) > MAX_TOKENS:
        raise PatternCompileError(
            f"{len(tokens)} tokens exceeds the {MAX_TOKENS}-token limit; this is "
            "prose or a literal block body, not a command to confirm"
        )
    if value_token is not None and not 0 <= value_token < len(tokens):
        raise PatternCompileError(
            f"value token {value_token} is outside the line's {len(tokens)} tokens"
        )

    parts = [
        CAPTURE if index == value_token else re.escape(token) for index, token in enumerate(tokens)
    ]

    if value_token is not None and len(parts) == 1:
        raise PatternCompileError(
            "a pattern whose only token is the captured one matches every "
            "single-word line in the configuration. Confirm a line that names "
            "its command."
        )

    return "^" + TOKEN_GAP.join(parts) + "$"


def build_scope(block_path: tuple[str, ...], *, generalise_numeric: bool = False) -> PatternScope:
    """Where the pattern is allowed to apply (D9, ADR 0011).

    Defaults to the literal-escaped confirmed header. Numeric generalisation is
    written out deliberately or not at all: `line vty 0 4` and `line vty 0 15`
    are different scopes, and quietly matching both is a defect wearing the shape
    of a convenience.
    """
    if not block_path:
        return PatternScope(block=None)

    entries: list[str] = []
    for header in block_path:
        escaped = re.escape(header)
        if generalise_numeric:
            escaped = re.sub(r"\d+", r"\\d+", escaped)
        entries.append("^" + escaped + "$")
    return PatternScope(block=tuple(entries))


def next_pattern_id(field: str, existing: tuple[str, ...]) -> str:
    """A readable, stable id in the convention the hand-written packs use.

    The `-admin-` infix is deliberate: reading a pack should make plain which
    patterns a vendor shipped and which this deployment learned, without
    cross-referencing the `source` field.
    """
    stem = f"p-{field.replace('_', '-')}-admin"
    taken = set(existing)
    for n in range(1, 1000):
        candidate = f"{stem}-{n:03d}"
        if candidate not in taken:
            return candidate
    raise PatternCompileError(f"no free pattern id for {field!r} after 999 attempts")


def check_editable_pattern(pattern: str) -> None:
    """Validate a regex an administrator edited by hand (D51).

    Editing is a requirement, not a concession — DEVELOPER_GUIDE.md §4 asks for it,
    because a pattern an administrator cannot correct is one they cannot verify.
    Accepting the edit *unchecked* is the failure: a hand-edited regex that no
    longer matches the confirmed line has silently stopped meaning what the human
    agreed to, and nothing downstream would notice.
    """
    if not pattern.startswith("^"):
        raise PatternRejectedError(
            f"pattern {pattern!r} is not anchored with ^. An unanchored pattern "
            "matches mid-line and will fire on statements it was never shown."
        )
    try:
        re.compile(pattern)
    except re.error as exc:
        raise PatternRejectedError(f"pattern {pattern!r} is not a valid regex: {exc}") from exc

    for construct, why in UNSAFE_CONSTRUCTS:
        if re.search(construct, pattern):
            raise PatternRejectedError(f"pattern {pattern!r} is refused: {why}")


def compile_pattern(
    example: TrainingExample,
    request: CompileRequest,
    *,
    existing_ids: tuple[str, ...] = (),
    pattern_override: str | None = None,
) -> PatternDef:
    """One recorded human decision becomes one pack pattern.

    Refuses, in order: a decision that confirmed nothing, a decision naming no
    administrator, a field outside the canonical schema, a line that cannot
    yield a boring pattern, an edited regex that is unsafe, and finally a pattern
    that does not match the very line it was compiled from.
    """
    if example.outcome is TrainingOutcome.REJECTED_NOT_SECURITY_RELEVANT:
        raise NotConfirmedError(
            f"example {example.example_id!r} was rejected as not security relevant; "
            "there is no mapping to compile"
        )
    if example.field is None:
        raise NotConfirmedError(
            f"example {example.example_id!r} records no confirmed field, so nothing "
            "was decided that could enter a pack"
        )
    if not example.confirmed_by.strip():
        raise NotConfirmedError(
            f"example {example.example_id!r} names no administrator. Trust "
            "originates in a person, not in a score."
        )
    if example.field not in CANONICAL_FIELD_NAMES:
        raise PatternCompileError(
            f"{example.field!r} is not a canonical security field. The training loop "
            "maps vendor syntax onto the existing schema; adding a field to the "
            "schema requires a pattern verifiable against a real corpus file "
            "(DEVELOPER_GUIDE.md §3), which is a different decision made by different people."
        )

    line = example.raw_line_scrubbed.strip()

    if request.value_token is None and request.literal_value is None:
        raise PatternCompileError(
            "a pattern must either capture a token or declare the literal value its "
            "presence asserts; this one does neither, so it would produce no fact"
        )

    if pattern_override is not None:
        regex = pattern_override
    else:
        regex = build_regex(line, request.value_token)

    check_editable_pattern(regex)

    if re.match(regex, line) is None:
        raise PatternRejectedError(
            f"pattern {regex!r} does not match the line it was confirmed from "
            f"({line!r}). Whatever this pattern now means, it is not what the "
            "administrator agreed to."
        )

    if request.value_token is not None:
        if re.compile(regex).groups < 1:
            raise PatternRejectedError(
                f"pattern {regex!r} captures nothing, but the decision names token "
                f"{request.value_token} as the value"
            )
        capture_value = "$1"
    else:
        capture_value = str(request.literal_value)

    pattern = PatternDef(
        id=next_pattern_id(example.field, existing_ids),
        field=example.field,
        scope=build_scope(request.block_path, generalise_numeric=request.generalise_numeric_scope),
        match=MatchSpec(type=MatchType.REGEX, pattern=regex),
        capture=CaptureSpec(value=capture_value, cast=request.cast),
        source=PatternSource.ADMIN_TRAINED,
        examples=(line,),
        provenance=PatternProvenance(
            training_example_id=example.example_id,
            suggestion_rank_accepted=example.outcome.accepted_rank,
            audit_seq=example.audit_seq,
        ),
    )

    failures = pattern.self_check()
    if failures:
        raise PatternRejectedError(
            f"compiled pattern {pattern.id} fails its own example check: {failures}"
        )
    return pattern
