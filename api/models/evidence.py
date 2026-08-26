"""Evidence — the atom every security claim in NIRIKSHAK is built from.

DEVELOPER_GUIDE.md Rule 2: every security-relevant field must carry evidence pointing at
the exact source file, line number and raw configuration line. If the system
cannot cite the line, it does not make the claim.

This module is deliberately tiny and has no dependency on anything else in the
project, because everything else depends on it.
"""

from __future__ import annotations

import hashlib
from typing import Any

from pydantic import BaseModel, ConfigDict, model_validator
from pydantic import Field as Constraint

from api.models.enums import SourceType

SHA256_HEX = r"^[0-9a-f]{64}$"


def sha256_hex(text: str) -> str:
    """SHA-256 of `text` as lowercase hex, over its UTF-8 encoding.

    Used both for line-level evidence and for the fleet-wide parse cache, so a
    line seen on device 1 is never re-parsed on device 400.
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class Evidence(BaseModel):
    """A pointer to the exact source text supporting one claim.

    Immutable by construction. `line_sha256` is derived from `raw_line` rather
    than accepted on trust: if a caller supplies one that disagrees, that is a
    bug worth failing loudly for, since it would mean the evidence and the text
    it cites had drifted apart.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    file_id: str = Constraint(min_length=1, description="Ingested artefact identifier")
    file_path: str = Constraint(min_length=1, description="Path as uploaded, for the report")

    line_start: int = Constraint(ge=1, description="1-based, inclusive")
    line_end: int = Constraint(ge=1, description="1-based, inclusive; equals line_start if single")

    raw_line: str = Constraint(min_length=1, description="Verbatim source text")
    line_sha256: str = Constraint(pattern=SHA256_HEX, description="SHA-256 of raw_line")

    source_type: SourceType
    locator: str | None = Constraint(default=None, description="XPath or JSONPath, when structured")
    block_path: tuple[str, ...] = Constraint(
        default=(), description="Enclosing block chain, e.g. ('line vty 0 4',)"
    )

    # -- validation --------------------------------------------------------

    @model_validator(mode="before")
    @classmethod
    def _derive_hash(cls, data: Any) -> Any:
        """Compute `line_sha256` from `raw_line` when absent; verify when present."""
        if not isinstance(data, dict):
            return data
        raw = data.get("raw_line")
        if not isinstance(raw, str):
            return data

        expected = sha256_hex(raw)
        supplied = data.get("line_sha256")
        if supplied is None:
            data = {**data, "line_sha256": expected}
        elif supplied != expected:
            raise ValueError(
                "line_sha256 does not match raw_line — evidence and the text it "
                f"cites have diverged (expected {expected}, got {supplied})"
            )
        return data

    @model_validator(mode="after")
    def _check_line_range(self) -> Evidence:
        if self.line_end < self.line_start:
            raise ValueError(f"line_end ({self.line_end}) precedes line_start ({self.line_start})")
        return self

    # -- convenience -------------------------------------------------------

    @property
    def is_multiline(self) -> bool:
        return self.line_end > self.line_start

    def cite(self) -> str:
        """Short human-readable citation for reports and test failures."""
        span = f"{self.line_start}-{self.line_end}" if self.is_multiline else f"{self.line_start}"
        return f"{self.file_path}:{span}"

    def __str__(self) -> str:
        return f"{self.cite()}  {self.raw_line.strip()}"
