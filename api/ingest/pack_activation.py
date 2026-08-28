"""Which pack version this deployment has chosen, per platform.

A pack file's `status:` is what it **shipped** as. This record is what the
deployment has **since decided**. Where they disagree, the record wins.

That split exists so activation never edits a reviewed file (decision D51).
`packs/builtin/` holds packs a person wrote and a reviewer read; a deployment
that rewrote their `status:` at runtime would leave the repository dirty,
invalidate their checksums, and destroy the one clean answer to "what did we
ship". Superseding a builtin pack with a trained one therefore adds a line here
rather than editing anything.

It is also what makes rollback trivial and exact: the previous pack file was
never modified, so pointing the record back at it restores the previous parse
behaviour byte for byte.

**Deployment state, not repository content.** Deleting this file falls back to
the shipped statuses, which is a sane and predictable failure mode: a fresh
checkout parses exactly as the packs in git say it should.

Living in `api/ingest/` rather than `api/train/` is deliberate: *reading* it is
part of deciding which packs are active, which is ingestion's job, and pack
loading must not depend on the layer that writes packs. `api/train/` imports this
to write; nothing here imports `api/train/`.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

HEADER = """\
# NIRIKSHAK — runtime pack activation record (P11, decision D51).
#
# A pack file's `status:` is what it SHIPPED as. This file records what this
# deployment has since activated. Where the two disagree, this file wins — which
# is how a trained pack supersedes a builtin one without any reviewed file being
# edited at runtime.
#
# Deployment state, not repository content. Delete it to fall back to the
# shipped statuses.

"""

ACTIVATION_RECORD = "activation.yaml"


@dataclass(frozen=True)
class ActivationRecord:
    """Platform id (`vendor/os_family`) to the pack version chosen for it."""

    active: dict[str, str]

    @classmethod
    def load(cls, root: Path) -> ActivationRecord:
        path = root / ACTIVATION_RECORD
        if not path.is_file():
            return cls(active={})
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        entries = raw.get("active") or {}
        if not isinstance(entries, dict):
            return cls(active={})
        return cls(active={str(k): str(v) for k, v in entries.items()})

    def save(self, root: Path) -> Path:
        root.mkdir(parents=True, exist_ok=True)
        path = root / ACTIVATION_RECORD
        dumped = yaml.safe_dump({"active": dict(sorted(self.active.items()))}, sort_keys=True)
        path.write_text(HEADER + dumped, encoding="utf-8")
        return path

    def with_active(self, pack_id: str, version: str) -> ActivationRecord:
        updated = dict(self.active)
        updated[pack_id] = version
        return ActivationRecord(active=updated)

    def version_for(self, pack_id: str) -> str | None:
        return self.active.get(pack_id)

    @property
    def is_empty(self) -> bool:
        return not self.active
