"""Safe ZIP extraction.

An archive from an untrusted source is two attacks waiting to happen, and both
are refusals here rather than surprises later:

**Zip Slip** — an entry named `../../etc/passwd` writes outside the extraction
directory. Every name is checked before anything is read.

**Zip bomb** — a few kilobytes that expand to gigabytes. Entry count, declared
uncompressed size, per-entry size and compression ratio are all capped, and the
declared sizes are checked *before* extraction rather than discovered during it.
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass
from pathlib import PurePosixPath

from api.ingest.validate import ValidationError
from api.models.ingestion import RejectionReason


@dataclass(frozen=True)
class ArchiveMember:
    name: str
    data: bytes


def _is_unsafe(name: str) -> bool:
    """True for absolute paths, drive letters, or anything climbing upward."""
    if not name or name.endswith("/"):
        return False
    if name.startswith(("/", "\\")):
        return True
    if len(name) > 1 and name[1] == ":":
        return True
    return any(part == ".." for part in PurePosixPath(name.replace("\\", "/")).parts)


def extract(
    data: bytes,
    *,
    max_entries: int,
    max_total_bytes: int,
    max_entry_bytes: int,
    max_ratio: int,
) -> list[ArchiveMember]:
    """Read a ZIP into memory, refusing anything hostile or oversized."""
    try:
        archive = zipfile.ZipFile(__import__("io").BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise ValidationError(
            RejectionReason.UNDECODABLE, f"not a readable ZIP archive: {exc}"
        ) from exc

    entries = [i for i in archive.infolist() if not i.is_dir()]

    if len(entries) > max_entries:
        raise ValidationError(
            RejectionReason.ARCHIVE_TOO_MANY_ENTRIES,
            f"the archive holds {len(entries)} files; the limit is {max_entries}",
        )

    for info in entries:
        if _is_unsafe(info.filename):
            raise ValidationError(
                RejectionReason.ARCHIVE_UNSAFE_PATH,
                f"entry {info.filename!r} escapes the extraction directory",
            )

    declared = sum(i.file_size for i in entries)
    if declared > max_total_bytes:
        raise ValidationError(
            RejectionReason.ARCHIVE_TOO_LARGE,
            f"the archive expands to {declared:,} bytes; the limit is {max_total_bytes:,}",
        )

    compressed = sum(i.compress_size for i in entries) or 1
    if declared // compressed > max_ratio:
        raise ValidationError(
            RejectionReason.ARCHIVE_COMPRESSION_BOMB,
            f"the archive expands {declared // compressed}x; the limit is {max_ratio}x",
        )

    members: list[ArchiveMember] = []
    for info in entries:
        if info.file_size > max_entry_bytes:
            raise ValidationError(
                RejectionReason.ARCHIVE_TOO_LARGE,
                f"entry {info.filename!r} is {info.file_size:,} bytes; "
                f"the per-file limit is {max_entry_bytes:,}",
            )
        with archive.open(info) as handle:
            members.append(ArchiveMember(name=info.filename, data=handle.read()))

    return members


def looks_like_zip(data: bytes) -> bool:
    return data[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
