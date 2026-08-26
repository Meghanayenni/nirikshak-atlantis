"""File validation — size, encoding, and telling text from binary.

The binary test is not the obvious one. Measured across real cases:

    utf-8 config     NUL=no   utf8=yes  printable=100%
    utf-16 config    NUL=YES  utf8=no   printable=46%    <- real text, has NULs
    latin-1 accents  NUL=no   utf8=no   printable=93%
    PNG header       NUL=yes  utf8=no   printable=69%
    ELF header       NUL=yes  utf8=YES  printable=8%     <- binary that decodes
    gzip             NUL=yes  utf8=no   printable=0%

Neither "contains NUL" nor "fails to decode" separates these: a UTF-16
configuration is full of NULs, and an ELF header decodes as UTF-8 quite happily.
The discriminator that works is the **printable ratio of the decoded text** —
configurations sit at 93-100%, binaries at 69% and below.

So: sniff the byte-order mark first (so UTF-16 and UTF-32 are decoded rather
than refused for their NULs), decode, then measure.
"""

from __future__ import annotations

from dataclasses import dataclass

from api.models.ingestion import RejectionReason

BOMS: tuple[tuple[bytes, str], ...] = (
    (b"\x00\x00\xfe\xff", "utf-32-be"),
    (b"\xff\xfe\x00\x00", "utf-32-le"),
    (b"\xef\xbb\xbf", "utf-8-sig"),
    (b"\xff\xfe", "utf-16-le"),
    (b"\xfe\xff", "utf-16-be"),
)

FALLBACK_ENCODINGS: tuple[str, ...] = ("utf-8", "cp1252")
"""Tried in order when there is no BOM. `cp1252` covers configurations saved
from a Windows editor with a stray accented character; it is deliberately not
`latin-1`, which decodes every byte sequence and would therefore accept binary
as text."""

TEXT_CONTROL_CHARS = frozenset({"\t", "\n", "\r", "\f", "\v"})


class ValidationError(Exception):
    """A file cannot be ingested. Carries the machine-readable reason."""

    def __init__(self, reason: RejectionReason, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class DecodedFile:
    text: str
    encoding: str
    printable_ratio: float


def detect_encoding(data: bytes) -> str | None:
    """Return the encoding named by a byte-order mark, if there is one."""
    for bom, encoding in BOMS:
        if data.startswith(bom):
            return encoding
    return None


def printable_ratio(text: str) -> float:
    """Fraction of characters that could plausibly appear in a configuration."""
    if not text:
        return 1.0
    printable = sum(1 for ch in text if ch.isprintable() or ch in TEXT_CONTROL_CHARS)
    return printable / len(text)


def decode(data: bytes, *, min_printable: float) -> DecodedFile:
    """Decode bytes to text, or raise with the reason it is not configuration."""
    if not data:
        raise ValidationError(RejectionReason.EMPTY, "the file is empty (0 bytes)")

    bom_encoding = detect_encoding(data)
    candidates = (bom_encoding,) if bom_encoding else FALLBACK_ENCODINGS

    text: str | None = None
    used = ""
    for encoding in candidates:
        if encoding is None:
            continue
        try:
            text = data.decode(encoding)
            used = encoding
            break
        except (UnicodeDecodeError, LookupError):
            continue

    if text is None:
        raise ValidationError(
            RejectionReason.UNDECODABLE,
            f"could not decode as {' or '.join(c for c in candidates if c)}; "
            "configuration files must be text",
        )

    # A stray U+FEFF surviving into the text would become part of line 1's
    # raw_line, silently changing that line's hash and every citation of it.
    # Tools that convert UTF-16 to UTF-8 sometimes leave one behind.
    if text.startswith("﻿"):
        text = text[1:]

    ratio = printable_ratio(text)
    if ratio < min_printable:
        raise ValidationError(
            RejectionReason.BINARY_CONTENT,
            f"only {ratio:.0%} of the decoded content is printable "
            f"(minimum {min_printable:.0%}); this looks like a binary file "
            "renamed as a configuration",
        )

    if not text.strip():
        raise ValidationError(RejectionReason.EMPTY, "the file contains only whitespace")

    return DecodedFile(text=text, encoding=used, printable_ratio=ratio)


def check_size(size_bytes: int, *, max_bytes: int, filename: str) -> None:
    if size_bytes == 0:
        raise ValidationError(RejectionReason.EMPTY, "the file is empty (0 bytes)")
    if size_bytes > max_bytes:
        raise ValidationError(
            RejectionReason.TOO_LARGE,
            f"{filename} is {size_bytes:,} bytes; the limit is {max_bytes:,}",
        )
