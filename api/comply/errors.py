"""Compliance-layer errors.

A malformed rulepack must not enter evaluation. The pattern is the one P4 and P5
established: refuse loudly rather than return something thin, because a rulepack
that silently loads with one broken rule produces an audit where a control looks
checked and was not.
"""

from __future__ import annotations


class ComplianceError(RuntimeError):
    """Base for every compliance-layer failure."""


class RulepackLoadError(ComplianceError):
    """A rule file exists but could not be read as a Rulepack.

    Covers invalid YAML, a rule failing contract validation, and duplicate rule
    ids. All of them mean the ruleset on disk is not the ruleset someone thinks
    they are running.
    """


class RulepackValidationError(ComplianceError):
    """A rulepack loaded, but self-check found rules that cannot be evaluated.

    Separate from `RulepackLoadError` because it says something different: the
    YAML was well-formed and every rule satisfied its contract, but a condition
    could never produce a verdict against any value of its declared type. That is
    an authoring mistake the contract cannot catch on its own — see decision D18.
    """

    def __init__(self, failures: dict[str, list[str]]) -> None:
        self.failures = failures
        detail = "\n".join(f"  {rule_id}: {'; '.join(msgs)}" for rule_id, msgs in failures.items())
        super().__init__(
            "rulepack self-check failed; these rules would abstain on every device "
            "while appearing to be supported:\n" + detail
        )
