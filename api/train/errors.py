"""Failures in the confirmation loop, each named for what a person did wrong.

Every one of these is raised rather than reported as a flag. A confirmation
enters a vendor pack permanently and changes how every future device of that
platform is read, so a caller that could ignore the answer would eventually
ignore it.
"""

from __future__ import annotations


class TrainError(RuntimeError):
    """Base for every failure in the confirmation loop."""


class QueueError(TrainError):
    """The training queue could not be assembled."""


class PatternCompileError(TrainError):
    """A confirmed line could not be turned into a pattern anyone should trust.

    Raised in preference to emitting a pattern that is technically valid and
    practically dangerous — one that matches every line, or one whose captured
    token is not in the line it was compiled from.
    """


class PatternRejectedError(TrainError):
    """An administrator's edited pattern failed validation (D51).

    Editing is allowed — DEVELOPER_GUIDE.md §4 requires it, because a pattern an
    administrator cannot verify is one they cannot correct. Editing without
    re-validation is not: a hand-edited regex that no longer matches the line it
    was confirmed from has silently stopped meaning what the human agreed to.
    """


class ActivationError(TrainError):
    """A pack could not be moved to ACTIVE."""


class NotConfirmedError(TrainError):
    """Something tried to compile a pattern without a recorded human decision.

    The one invariant the whole learning loop rests on: a suggestion is never
    authority. `api/learn/` proposes, an administrator decides, and only the
    recorded decision compiles.
    """
