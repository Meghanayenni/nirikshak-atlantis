"""`packs/archive/` — durable, verifiable, and unreachable by the loader.

DEF-18: two stored audit runs cite `cisco/ios 1.1.5`, a trained pack deleted at
P15. `FindingProvenance` records a pack version precisely so a verdict can name
the data that produced it; a version that resolves to nothing is a version
number, not reproducibility.

This module asserts the three properties the archive has to hold at once:

  **durable** — the files are in the repository, not in a scratch directory that
  does not survive the machine;

  **verifiable** — each still matches its own declared checksum, so the archived
  1.1.5 is the bytes that read those two runs rather than a reconstruction;

  **inert** — the activation scan never sees it. Every archived file carries
  `status: active` as written, so a copy back into `packs/trained/` would give a
  platform two active versions and the loader would refuse (D46).

It does **not** assert that anything resolves a version *through* the archive.
Nothing does. That is the open half of DEF-18 and it needs a decision about how
pack storage is organised, not a directory.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from api.ingest.pack_activation import ACTIVATION_RECORD
from api.ingest.pack_checksum import verify_file
from api.ingest.packs import PACK_ROOTS, REPO_ROOT, discover_packs, load_pack

ARCHIVE_ROOT = REPO_ROOT / "packs" / "archive"

ORPHANED_BY_DEF_18 = ("cisco_ios", "1.1.5")
"""The one archived version a stored audit run on this deployment cites."""


def _archived_packs() -> list[Path]:
    return sorted(p for p in ARCHIVE_ROOT.rglob("*.yaml"))


# ---------------------------------------------------------------------------
# Durable
# ---------------------------------------------------------------------------


def test_the_archive_exists_in_the_repository() -> None:
    assert ARCHIVE_ROOT.is_dir(), (
        "packs/archive/ is missing. It holds the only surviving copy of pack "
        "versions that stored findings cite; recovering it a second time is not "
        "something anyone should be relying on."
    )


def test_the_version_def_18_orphaned_is_archived() -> None:
    """Named explicitly, because this is the file the defect is about."""
    platform, version = ORPHANED_BY_DEF_18
    assert (ARCHIVE_ROOT / platform / f"{version}.yaml").is_file()


def test_every_archived_file_is_a_loadable_vendor_pack() -> None:
    """Archived, not abandoned — a file nothing can parse records nothing."""
    for path in _archived_packs():
        if path.name.startswith("activation"):
            continue
        pack = load_pack(path)
        assert pack.pack_version == path.stem


# ---------------------------------------------------------------------------
# Verifiable
# ---------------------------------------------------------------------------


def test_every_archived_pack_still_verifies_against_its_own_checksum() -> None:
    """This is what makes the archive evidence rather than a copy.

    A pack whose bytes no longer match its declared digest cannot support the
    claim "this is what read that finding" — which is the entire reason to keep
    it.
    """
    failures = []
    for path in _archived_packs():
        if path.name.startswith("activation"):
            continue
        result = verify_file(path)
        if not result.verified:
            failures.append(f"{path.parent.name}/{path.name}: {result.describe()}")
    assert failures == [], "\n".join(failures)


# ---------------------------------------------------------------------------
# Inert
# ---------------------------------------------------------------------------


def test_the_archive_is_not_a_pack_root() -> None:
    """The activation scan must never reach these files.

    Asserted against containment rather than equality: `discover_packs` uses
    `rglob`, so an archive nested under a pack root would be found just as
    surely as one named as a root.
    """
    for root in PACK_ROOTS:
        assert ARCHIVE_ROOT != root
        assert root not in ARCHIVE_ROOT.parents, (
            f"packs/archive/ sits under the pack root {root.name}, so the loader "
            "would discover ten packs that all declare themselves active"
        )


def test_discovery_returns_no_archived_version() -> None:
    """The property above, observed end to end rather than inferred from paths."""
    archived = {(p.parent.name, p.stem) for p in _archived_packs() if p.stem[0].isdigit()}
    discovered = {
        (f"{pack.vendor}_{pack.os_family}", pack.pack_version) for pack in discover_packs()
    }
    assert archived & discovered == set(), (
        f"the loader discovered archived versions: {sorted(archived & discovered)}"
    )


def test_no_archived_file_uses_the_activation_record_filename() -> None:
    """A loader pointed at this directory must not be able to activate anything.

    `active_packs(root=...)` reads `activation.yaml` from whichever root it is
    given. The deployment's record is kept here for the history, under a name
    the loader does not recognise.
    """
    assert not (ARCHIVE_ROOT / ACTIVATION_RECORD).exists()
    preserved = ARCHIVE_ROOT / "activation-record-as-found.yaml"
    assert preserved.is_file()
    record = yaml.safe_load(preserved.read_text(encoding="utf-8"))
    assert record["active"]["cisco/ios"] == "1.1.5", (
        "the preserved record should still show the activation that produced the "
        "orphaned findings"
    )


def test_the_archive_is_committed_rather_than_ignored() -> None:
    """`packs/trained/*` is gitignored deployment state. This deliberately is not.

    D67 reasoned that removing a trained pack was safe because the directory is
    gitignored. That was true of the repository and false of the database beside
    it (ADR 0030). An archive inheriting the same ignore rule would inherit the
    same defect.
    """
    ignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    offenders = [
        line
        for line in ignore.splitlines()
        if line.strip().startswith("packs/") and "archive" in line
    ]
    assert offenders == [], f".gitignore excludes the archive: {offenders}"


@pytest.mark.parametrize("platform", ["cisco_ios", "juniper_junos", "arista_eos"])
def test_each_archived_platform_kept_at_least_one_version(platform: str) -> None:
    assert list((ARCHIVE_ROOT / platform).glob("*.yaml"))
