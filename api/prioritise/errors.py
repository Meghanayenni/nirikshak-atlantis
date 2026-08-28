"""Failures in the prioritisation layer.

Every one is raised rather than reported as a flag. Prioritisation decides what
an operator fixes first; a caller that could ignore an error here would ignore it
and act on a ranking that does not mean what it appears to mean.
"""

from __future__ import annotations


class PrioritiseError(RuntimeError):
    """Base for every failure in the prioritisation layer."""


class ExposureError(PrioritiseError):
    """An exposure assessment was constructed that claims more than it knows.

    The one failure this layer exists to prevent: a score attached to an
    assessment that never determined anything, or a determination with no score
    behind it. Either would turn "we could not tell" into a number an operator
    would sort by.
    """


class BaselineError(PrioritiseError):
    """A peer baseline was asked for something its cohort cannot support."""
