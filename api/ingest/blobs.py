"""Content-addressed store for raw configuration files.

Files are kept **verbatim**. No normalisation, no scrubbing, no reformatting:
evidence fidelity depends on the bytes being exactly what the operator uploaded,
and a finding that cites a line must be able to show that line as it was
written.

Secrets are scrubbed before *inference* (P10), not before storage. Redacting
here would destroy the evidence a finding depends on — a report saying "your
SNMP community is weak" while displaying `<redacted>` is not evidence. That
makes this directory the protection boundary, and it is precisely what decision
R11 would encrypt at rest.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

CHUNK = 64 * 1024


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_stream(source: Path, chunk: int = CHUNK) -> str:
    digest = hashlib.sha256()
    with source.open("rb") as handle:
        while block := handle.read(chunk):
            digest.update(block)
    return digest.hexdigest()


def blob_path(root: Path, file_id: str) -> Path:
    """Two-level fan-out, so a fleet-sized store stays navigable."""
    return root / file_id[:2] / file_id


def exists(root: Path, file_id: str) -> bool:
    return blob_path(root, file_id).is_file()


def store(root: Path, file_id: str, data: bytes) -> Path:
    """Write the blob if it is not already present. Returns its path.

    Content-addressed, so writing the same file twice is a no-op rather than a
    conflict — which is what makes duplicate detection free.
    """
    path = blob_path(root, file_id)
    if path.is_file():
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def read(root: Path, file_id: str) -> bytes:
    return blob_path(root, file_id).read_bytes()


def relative(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root)).replace("\\", "/")
    except ValueError:  # pragma: no cover - path outside the store
        return str(path)
