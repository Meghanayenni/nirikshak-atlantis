"""Remediation-layer errors.

The pattern P4, P5 and P6 established: refuse loudly rather than return
something thin. A snippet library that silently loads with one malformed entry
produces a report where a rule looks remediable and is not — or, far worse, one
where an operator is handed a command nobody checked.

Every failure here happens at **load** time, not at render time. By the moment a
report is being written the library is either wholly valid or it did not open.
"""

from __future__ import annotations


class RemediationError(RuntimeError):
    """Base for every remediation-layer failure."""


class SnippetLoadError(RemediationError):
    """A snippet file exists but could not be read as a RemediationSnippet.

    Covers invalid YAML, schema violations, contract violations and duplicate
    snippet ids. All of them mean the library on disk is not the library someone
    thinks they are shipping.
    """


class SnippetLibraryError(RemediationError):
    """The library loaded, but the set of snippets is not internally consistent.

    Separate from `SnippetLoadError` because it says something different: every
    file was well-formed and every snippet satisfied its own contract, but they
    do not agree with each other — a dependency naming a snippet that is not
    present, or a cycle among `depends_on`. Neither is visible from inside a
    single file.
    """

    def __init__(self, problems: list[str]) -> None:
        self.problems = problems
        super().__init__(
            "the snippet library is not internally consistent:\n"
            + "\n".join(f"  {p}" for p in problems)
        )
