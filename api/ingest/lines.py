"""Physical line splitting, counting and hashing.

**Never use `str.splitlines()`.** Measured on CPython 3.11, it treats nine
characters beyond CR/LF/CRLF as line breaks — U+000B, U+000C, U+001C, U+001D,
U+001E, U+0085, U+2028, U+2029 among them. A banner block containing a vertical
tab, entirely plausible in a copy-pasted MOTD, splits into extra lines.

That matters more than it sounds. Every piece of evidence NIRIKSHAK produces
cites a line number. If our numbers disagree with the ones an operator sees when
they open the file, every citation in every report is quietly wrong, and nothing
surfaces the error until somebody checks by hand.

A test asserts the divergence case, and an architecture test asserts
`.splitlines()` appears nowhere under `api/`.
"""

from __future__ import annotations

import hashlib
import re

from api.models.ingestion import LineRecord

LINE_BREAK = re.compile(r"\r\n|\r|\n")
"""The only three sequences that end a physical line in a configuration file."""


def split_lines(text: str) -> list[str]:
    """Split on CRLF, CR or LF, and nothing else.

    A single trailing terminator ends the last line rather than starting an
    empty one; two trailing terminators mean there genuinely is a blank line at
    the end. Getting this wrong shifts the count by one on almost every real
    file (finding F3).
    """
    if text == "":
        return []

    parts = LINE_BREAK.split(text)
    if parts and parts[-1] == "":
        parts.pop()
    return parts


def count_lines(text: str) -> int:
    return len(split_lines(text))


def hash_line(text: str) -> str:
    """SHA-256 of one line's text, as stored in the fleet-wide cache."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def line_records(text: str) -> list[LineRecord]:
    """Every physical line with its 1-based number and hash."""
    return [
        LineRecord(line_number=n, text=line, line_sha256=hash_line(line))
        for n, line in enumerate(split_lines(text), start=1)
    ]


def reconstruct(lines: list[str]) -> str:
    """Rebuild the text from split lines, normalised to LF.

    Used by the losslessness test: reconstructing from `config_line` and
    `line_cache` must reproduce the decoded text exactly, which is the same
    guarantee decision R4 requires of the block parser one layer up.
    """
    return "\n".join(lines)


def normalise_terminators(text: str) -> str:
    """Normalise CRLF and CR to LF without changing any line's content."""
    return LINE_BREAK.sub("\n", text)
