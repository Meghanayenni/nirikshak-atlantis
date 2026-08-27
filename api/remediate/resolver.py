"""Resolving remediation for a finding, and ordering what comes back.

**Resolution, not generation** (Rule 4). Every command this package can return
was read from a file under `snippets/`. There is no template, no format string
that builds a command, no fallback to a similar platform, and no model. A rule
with no vetted snippet resolves to `NO_SNIPPET` and the operator is told so in
the report, in one specific sentence, every time.

This module deliberately carries **no verdict vocabulary**. It is told whether a
finding is actionable; it does not decide, and it cannot see a verdict, a
finding or the rule engine. That is the same separation `api/analyse/` has, for
the same reason: remediation must not become a second place where something that
looks like a compliance decision gets made.

## Ordering

`order_snippets` answers "in what sequence would an operator apply these?".
Three keys, in priority order:

1. **Dependency.** A snippet naming another in `depends_on` is applied after it.
2. **Lockout risk, ascending.** A high-risk change goes *last*. Disabling an
   insecure management protocol before its replacement is verified is precisely
   how an operator gets stranded outside their own device.
3. **`order_hint`, then `snippet_id`.** So the sequence is total and stable, and
   two runs over the same set produce the same list.

It is built and unit-tested against constructed snippets. **It has never ordered
a real one**, because the library is empty.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from api.models.enums import LockoutRisk
from api.models.snippet import RemediationSnippet
from api.remediate.errors import SnippetLibraryError
from api.remediate.library import SnippetLibrary

NO_REMEDIATION_STATEMENT = "No vetted remediation is available for this platform and rule."
"""What the operator is told when nothing resolves.

Fixed text, asserted by tests, rendered without suppression. The alternative -
an empty remediation panel - is indistinguishable from a panel that failed to
render, and it invites the reader to assume the fix is obvious and type it
themselves. Saying nothing is available is a smaller failure than implying
something is.
"""


class ResolutionOutcome(StrEnum):
    """Why a finding did or did not receive a command."""

    RESOLVED = "resolved"
    """A vetted snippet exists for this platform and rule."""

    NO_SNIPPET = "no_snippet"
    """The library holds nothing for this (vendor, os_family, rule_id).

    The current outcome for every finding on every device: the library is empty
    because no vendor documentation has been sourced (decision D27).
    """

    NOT_ACTIONABLE = "not_actionable"
    """The finding is not a FAIL, so there is nothing to remediate.

    Distinct from `NO_SNIPPET` on purpose. "We have no fix for this" and "this
    does not need fixing" are opposite messages, and a report that renders them
    identically teaches the reader to ignore both.
    """

    PLATFORM_UNKNOWN = "platform_unknown"
    """The device's vendor or OS family was never identified.

    A snippet key is `(vendor, os_family, rule_id)`. Without the first two there
    is nothing to look up, and guessing the platform in order to produce a
    command is the exact failure Rule 4 exists to prevent.
    """


@dataclass(frozen=True)
class RemediationResolution:
    """The outcome of one lookup, and the snippet if there was one.

    Frozen, and always carries a `statement`. A caller cannot obtain a resolution
    that has no explanation attached, so a template cannot render a blank where a
    reason belongs.
    """

    outcome: ResolutionOutcome
    snippet: RemediationSnippet | None = None
    statement: str = NO_REMEDIATION_STATEMENT

    @property
    def has_commands(self) -> bool:
        return self.snippet is not None

    def __post_init__(self) -> None:
        resolved = self.outcome is ResolutionOutcome.RESOLVED
        if resolved and self.snippet is None:
            raise ValueError("a RESOLVED resolution must carry the snippet it resolved to")
        if not resolved and self.snippet is not None:
            raise ValueError(f"a {self.outcome.value} resolution must not carry a snippet")


def resolve(
    library: SnippetLibrary,
    *,
    rule_id: str,
    vendor: str | None,
    os_family: str | None,
    actionable: bool,
) -> RemediationResolution:
    """Look up remediation for one finding on one platform.

    `actionable` is supplied by the caller rather than derived here: this package
    must not be able to see a verdict. The caller reads `Finding.is_actionable`,
    which is the one place that decision lives.

    Every branch that fails to find a snippet returns the same operator-facing
    sentence with a different machine-readable outcome. The report shows the
    sentence; the API exposes the outcome, so a future UI can distinguish them
    without the two ever disagreeing about what is available.
    """
    if not actionable:
        return RemediationResolution(
            outcome=ResolutionOutcome.NOT_ACTIONABLE,
            statement="No remediation is proposed: this finding is not a failure.",
        )

    if not vendor or not os_family:
        return RemediationResolution(outcome=ResolutionOutcome.PLATFORM_UNKNOWN)

    snippet = library.lookup(vendor, os_family, rule_id)
    if snippet is None:
        return RemediationResolution(outcome=ResolutionOutcome.NO_SNIPPET)

    return RemediationResolution(
        outcome=ResolutionOutcome.RESOLVED,
        snippet=snippet,
        statement=f"Vetted by {snippet.vetted_by}, checked against {snippet.reference}.",
    )


_LOCKOUT_RANK: dict[LockoutRisk, int] = {
    LockoutRisk.NONE: 0,
    LockoutRisk.LOW: 1,
    LockoutRisk.HIGH: 2,
}


def _sort_key(snippet: RemediationSnippet) -> tuple[int, int, str]:
    return (
        _LOCKOUT_RANK[snippet.impact.lockout_risk],
        snippet.order_hint,
        snippet.snippet_id,
    )


def order_snippets(snippets: tuple[RemediationSnippet, ...]) -> tuple[RemediationSnippet, ...]:
    """The sequence an operator would apply these in.

    Dependencies pointing outside the supplied set are ignored rather than
    treated as unsatisfied. A per-device report resolves only the rules that
    failed on that device, so a snippet may legitimately depend on one whose rule
    passed here - and refusing to order the set because of that would deny the
    operator a sequence over a prerequisite that is already satisfied.

    Raises when the supplied set contains a cycle. A truncated ordering would
    silently drop commands, and an operator counting six fixes and receiving five
    has no way to know which is missing.
    """
    if not snippets:
        return ()

    present = {s.snippet_id: s for s in snippets}
    pending = {
        sid: {d for d in s.depends_on if d in present and d != sid} for sid, s in present.items()
    }

    ordered: list[RemediationSnippet] = []
    while pending:
        ready = [sid for sid, deps in pending.items() if not deps]
        if not ready:
            raise SnippetLibraryError(
                [
                    "dependency cycle among: " + ", ".join(sorted(pending)),
                    "no application order exists for this set",
                ]
            )

        chosen = min(ready, key=lambda sid: _sort_key(present[sid]))
        ordered.append(present[chosen])
        del pending[chosen]
        for deps in pending.values():
            deps.discard(chosen)

    return tuple(ordered)
