"""The one reproducible digest convention for a vendor pack file.

Defect DEF-13: from P4 until P11 a pack's `checksum` was *declared and never
verified*. The three packs shipped before this module existed carried values
matching no computable digest of anything, and `tests/unit/test_rulepack_loading.py`
recorded that as "a mistake worth not repeating" while the mistake went on
shipping. A declared-but-false integrity value is worse than none: it looks like
a control and is a decoration.

That mattered little while every pack was written by hand and reviewed in a pull
request. It matters at P11, where `api/train/` writes pack files at runtime into
`packs/trained/`. Those files are not reviewed by anybody before they are loaded,
so the digest is the only thing standing between an edited pack and a parser that
trusts it.

**The convention**, stated once, here, and nowhere else:

    sha256 of the file's bytes as stored — LF line endings, which
    `.gitattributes` (`* text=auto eol=lf`) guarantees on every checkout — with
    the `checksum:` line removed entirely.

Removing the line rather than blanking it is what makes the digest a fixed
point: the value being written does not participate in the value being computed,
so a pack can be stamped without iterating to convergence.

CRLF is normalised before hashing. A pack written on Windows and one written on
Linux are the same pack, and an integrity check that disagrees about that
reports tampering where there is none — the false alarm ADR 0007 warns against.

This lives in `api/ingest/` rather than `api/train/` because verification
happens at **load**, which is ingestion's concern. Putting it in the training
layer would mean every pack read depended on the layer that writes packs, and
`api/train/` would become load-bearing for a deployment that never trains
anything.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

CHECKSUM_FIELD = b"checksum:"
"""The line excluded from the digest. Matched at the start of a line only."""

DIGEST_PREFIX = "sha256:"
"""Matches `SHA256_PREFIXED` in the pack contract."""


class PackChecksumError(RuntimeError):
    """A pack's declared checksum does not verify against its own bytes."""


def canonical_bytes(raw: bytes) -> bytes:
    """The exact byte sequence the digest is taken over.

    `split(b"\n")` rather than `splitlines()` deliberately: `splitlines` breaks
    on nine characters beyond CR/LF, and a pack whose digest depended on a
    vertical tab being a line separator would be reproducible only by accident
    (finding F1, guarded repository-wide).
    """
    lines = raw.replace(b"\r\n", b"\n").split(b"\n")
    return b"\n".join(line for line in lines if not line.startswith(CHECKSUM_FIELD))


def compute(raw: bytes) -> str:
    """The digest a pack with these bytes must declare."""
    return DIGEST_PREFIX + hashlib.sha256(canonical_bytes(raw)).hexdigest()


def declared(raw: bytes) -> str | None:
    """The digest the file claims, or None when it declares none.

    Read from the bytes rather than from the parsed model so that verification
    does not depend on the pack being constructible — a pack that fails contract
    validation should still be able to report whether it was modified.
    """
    for line in raw.replace(b"\r\n", b"\n").split(b"\n"):
        if line.startswith(CHECKSUM_FIELD):
            return line[len(CHECKSUM_FIELD) :].strip().decode("utf-8", errors="replace")
    return None


@dataclass(frozen=True)
class ChecksumResult:
    """What verification found. Reported rather than raised, so a caller can
    decide whether a mismatch is fatal — it is at activation, and on loading an
    ACTIVE pack, and it is not for a DRAFT still being edited."""

    path: str
    declared: str | None
    computed: str

    @property
    def is_declared(self) -> bool:
        return self.declared is not None

    @property
    def verified(self) -> bool:
        return self.declared == self.computed

    def describe(self) -> str:
        if not self.is_declared:
            return f"{self.path} declares no checksum"
        if self.verified:
            return f"{self.path} verified"
        return (
            f"{self.path} declares {self.declared} but its bytes compute "
            f"{self.computed} — the file has changed since it was stamped, or it "
            "was stamped by something that does not use this convention"
        )


def verify_bytes(raw: bytes, *, path: str = "<bytes>") -> ChecksumResult:
    return ChecksumResult(path=path, declared=declared(raw), computed=compute(raw))


def verify_file(path: Path) -> ChecksumResult:
    return verify_bytes(path.read_bytes(), path=path.name)


def stamp(raw: bytes) -> bytes:
    """Return these bytes with their `checksum:` line set to the correct digest.

    Used when writing a trained pack, and when correcting a legacy one. The
    digest is computed from `canonical_bytes`, which excludes the line being
    replaced, so stamping is idempotent: stamping twice changes nothing.
    """
    digest = compute(raw)
    normalised = raw.replace(b"\r\n", b"\n")
    lines = normalised.split(b"\n")
    replaced = False
    out: list[bytes] = []
    for line in lines:
        if line.startswith(CHECKSUM_FIELD):
            out.append(CHECKSUM_FIELD + b" " + digest.encode("utf-8"))
            replaced = True
        else:
            out.append(line)
    if not replaced:
        raise PackChecksumError(
            "cannot stamp a pack that declares no `checksum:` line; the field is "
            "required on an ACTIVE pack and must exist before it can be filled"
        )
    return b"\n".join(out)
