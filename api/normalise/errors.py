"""Normalise-layer errors.

Same principle as the parse layer: a normaliser that cannot do its job says so
rather than returning a thin canonical model. A CSM with fields quietly missing
looks like a device that simply has nothing configured, and every rule evaluated
against it would read UNKNOWN while the file appeared to have been handled.
"""

from __future__ import annotations


class NormalisationError(RuntimeError):
    """Base for every normalise-layer failure."""


class ConflictingSourcesError(NormalisationError):
    """Two parse results disagree about the same canonical field.

    P5 builds one CSM per configuration file (decision D14), so this cannot
    arise from the supported path. It exists because the multi-file signature is
    already in place for a later fleet layer, and merge semantics are exactly the
    thing that must not be invented quietly: two files disagreeing about the same
    canonical control is a question for a human, not a tie for the code to break.
    """

    def __init__(self, field: str, values: list[object]) -> None:
        self.field = field
        self.values = values
        super().__init__(
            f"sources disagree about {field!r}: {values!r}. Merging would mean "
            "choosing one, and nothing here is entitled to choose. Multi-file "
            "device grouping is deferred — see decision D14."
        )


class MissingPackError(NormalisationError):
    """Normalisation was asked for without the pack that produced the parse.

    The pack carries the capability and default knowledge the absence rules run
    on. Without it every absent field would resolve identically, and the result
    would be indistinguishable from a platform that documents nothing.
    """
