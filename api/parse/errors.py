"""Parse-layer errors.

A parser that cannot handle its input must say so. Returning an empty tree, or a
partial one, produces facts that look complete and are not — and those facts
arrive with line numbers attached, which makes them convincing.
"""

from __future__ import annotations

from api.models.enums import SyntaxMode


class ParseError(RuntimeError):
    """Base for every parse-layer failure."""


class UnsupportedSyntaxModeError(ParseError):
    """A syntax mode exists in the contract but is not implemented yet (D8).

    Raised rather than returning an empty `ConfigTree`. An empty tree would be
    indistinguishable from a configuration with nothing in it: every field would
    read UNKNOWN, the file would look cleanly parsed, and nothing would say the
    parser had simply declined.
    """

    def __init__(self, mode: SyntaxMode, phase: str = "a later phase") -> None:
        self.mode = mode
        self.phase = phase
        super().__init__(
            f"syntax mode {mode!s} is not implemented (planned for {phase}). "
            "The parser refuses rather than returning an empty tree, because an "
            "empty tree would look like a successfully parsed empty configuration."
        )


class CastError(ParseError):
    """A captured value could not be converted to its declared type.

    Never resolved by guessing. A malformed value yields no fact at all, because
    a plausible-looking substitute is worse than an admitted gap.
    """

    def __init__(self, raw: str, cast: str, detail: str = "") -> None:
        self.raw = raw
        self.cast = cast
        super().__init__(f"cannot read {raw!r} as {cast}" + (f": {detail}" if detail else ""))


class UnterminatedLiteralBlockError(ParseError):
    """A literal block opened and the file ended before its terminator."""

    def __init__(self, name: str, line_number: int, terminator: str) -> None:
        super().__init__(
            f"literal block {name!r} opened at line {line_number} and was never "
            f"closed by {terminator!r}"
        )
