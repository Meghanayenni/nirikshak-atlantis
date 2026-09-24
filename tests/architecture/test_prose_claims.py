"""Prose that states what the system lacks, or how much of it there is, is checked.

Six paragraphs drifted at once before ADR 0059, and all six understated the
system: a document said the snippet library was empty beside twenty snippets,
said a JunOS surface was "not read" two paragraphs after the ADR that read it,
and described cohorts of 4, 3 and 3 over a corpus of nineteen files. Nothing was
checking. Numeric claims about frameworks and counts were already reconciled
(`test_framework_claims`, `test_architecture_document`); claims of **absence**
were not, and they are the ones that expire silently as the system grows.

**This is a registry, not a scanner.** The six drifted sentences used six
unrelated phrasings; a lexical net for "absence-shaped" prose would have missed
most of them and flagged plenty that are true. So each load-bearing claim is
written down here — document, exact phrase, and a predicate derived from the
code — the same shape as `test_skip_guards`' registries:

  * while the phrase is in the document, the predicate must hold; when the
    capability arrives, this fails and names the sentence to change;
  * if the phrase is gone, the entry must go too, so the registry cannot
    describe claims nobody makes any more.

What it does not do: find the next unregistered claim. That still needs a
reader. It makes a registered claim impossible to leave stale.
"""

from __future__ import annotations

import functools
import hashlib
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


@functools.lru_cache(maxsize=1)
def _packs():
    from api.ingest.packs import load_active_packs

    return tuple(load_active_packs(use_cache=False))


def _pack(vendor: str, os_family: str):
    return next(p for p in _packs() if (p.vendor, p.os_family) == (vendor, os_family))


@functools.lru_cache(maxsize=1)
def _corpus():
    """(split, platform, csm) for every non-holdout file, through the real pipeline."""
    from api.config import settings
    from api.ingest.device_identity import extract_identity
    from api.ingest.lines import split_lines
    from api.ingest.packs import find_pack
    from api.ingest.vendor_detect import detect_vendor
    from api.normalise.service import build_csm
    from api.parse.service import parse_configuration

    manifest = yaml.safe_load((REPO_ROOT / "corpus" / "MANIFEST.yaml").read_text(encoding="utf-8"))
    out = []
    for entry in manifest["files"]:
        if entry["split"] == "holdout":
            continue  # never opened
        path = REPO_ROOT / "corpus" / entry["path"]
        text = path.read_text(encoding="utf-8")
        lines = split_lines(text)
        det = detect_vendor(
            list(_packs()),
            lines,
            filename=path.name,
            min_score=settings.detection_min_score,
            min_margin=settings.detection_min_margin,
        )
        pack = find_pack(det.vendor, det.os_family)
        fid = hashlib.sha256(path.read_bytes()).hexdigest()
        parsed = parse_configuration(text, pack, file_id=fid, file_path=entry["path"])
        identity = extract_identity(pack, lines, file_id=fid, file_path=entry["path"])
        csm = build_csm(parsed, pack, device_id=fid, detected_identity=identity)
        out.append((entry["split"], f"{det.vendor}/{det.os_family}", csm))
    return tuple(out)


def _no_interface_roles() -> bool:
    return all(not p.interface_roles for p in _packs())


def _no_defaults_or_capabilities() -> bool:
    return all(not p.defaults and not p.capabilities for p in _packs())


def _junos_and_eos_read_no_canonical_field() -> bool:
    from api.parse.fields import declared_fields

    return not declared_fields(_pack("juniper", "junos")) and not declared_fields(
        _pack("arista", "eos")
    )


def _cohorts_are_9_5_4_1() -> bool:
    sizes = Counter(platform for _, platform, _ in _corpus())
    return sizes == Counter({"cisco/ios": 9, "juniper/junos": 5, "arista/eos": 4, "cisco/nxos": 1})


def _eight_ios_baselines_no_deviation() -> bool:
    from api.prioritise.service import fleet_baseline

    fleet = fleet_baseline([csm for _, _, csm in _corpus()])
    compared = [b for b in fleet.baselines if b.outcome.value == "compared"]
    return (
        len(compared) == 8 and {b.cohort for b in compared} == {"cisco/ios"} and not fleet.outliers
    )


def _six_acls_none_dropped_5_4_3() -> bool:
    from api.analyse.service import analyse_device

    analysed = dropped = 0
    kinds: Counter = Counter()
    for _, _, csm in _corpus():
        result = analyse_device(csm)
        analysed += len(result.acls)
        dropped += len(csm.acl_failures)
        kinds.update(result.summary())
    return (analysed, dropped) == (6, 0) and (
        kinds["shadowed"],
        kinds["redundant"],
        kinds["overly_permissive"],
    ) == (5, 4, 3)


def _seven_cisco_dev_devices() -> bool:
    dev = Counter(p for split, p, _ in _corpus() if split == "dev" and p.startswith("cisco/"))
    return dev == Counter({"cisco/ios": 6, "cisco/nxos": 1})


def _every_file_has_an_active_pack() -> bool:
    return all(csm.source.pack_versions for _, _, csm in _corpus())


def _twenty_snippets_three_platforms() -> bool:
    from api.remediate.library import load_active_library

    lib = load_active_library()
    return len(lib.snippets) == 20 and len({(s.vendor, s.os_family) for s in lib.snippets}) == 3


@dataclass(frozen=True)
class Claim:
    document: str
    phrase: str
    holds: Callable[[], bool]
    means: str


CLAIMS: tuple[Claim, ...] = (
    Claim(
        "docs/architecture.md",
        "but **no pack declares one**",
        _no_interface_roles,
        "no pack declares management-plane interface_roles",
    ),
    Claim(
        "docs/SOURCING_BACKLOG.md",
        "**No pack declares one**",
        _no_interface_roles,
        "no pack declares management-plane interface_roles",
    ),
    Claim(
        "docs/SOURCING_BACKLOG.md",
        "**Zero** platform defaults and **zero** capability claims ship",
        _no_defaults_or_capabilities,
        "no pack ships a platform default or a capability claim",
    ),
    Claim(
        "docs/architecture.md",
        "No platform default and no capability claim ships",
        _no_defaults_or_capabilities,
        "no pack ships a platform default or a capability claim",
    ),
    Claim(
        "docs/architecture.md",
        "neither pack reads a canonical field, so there is nothing to\ncompare",
        _junos_and_eos_read_no_canonical_field,
        "the JunOS and EOS packs declare no canonical-field pattern",
    ),
    Claim(
        "docs/architecture.md",
        "Every one of the nineteen files has an active pack",
        _every_file_has_an_active_pack,
        "every non-holdout corpus file is read by an active pack",
    ),
    Claim(
        "docs/SOURCING_BACKLOG.md",
        "**Cisco IOS 9, JunOS 5, EOS 4,\nNX-OS 1**",
        _cohorts_are_9_5_4_1,
        "the cohort sizes derived from the corpus",
    ),
    Claim(
        "docs/SOURCING_BACKLOG.md",
        "eight baselines are compared and\nno device deviates",
        _eight_ios_baselines_no_deviation,
        "eight compared baselines, all Cisco IOS, and no outlier",
    ),
    Claim(
        "docs/SOURCING_BACKLOG.md",
        "six access\nlists are analysed across three dialects",
        _six_acls_none_dropped_5_4_3,
        "six ACLs analysed, none dropped, 5 shadowed / 4 redundant / 3 overly permissive",
    ),
    Claim(
        "docs/SOURCING_BACKLOG.md",
        "Seven Cisco development devices — six IOS, one\nNX-OS",
        _seven_cisco_dev_devices,
        "the Cisco development split, by platform",
    ),
    Claim(
        "docs/SOURCING_BACKLOG.md",
        "`snippets/` holds twenty\nsnippets",
        _twenty_snippets_three_platforms,
        "twenty vetted snippets across three platforms",
    ),
)


def _text(document: str) -> str:
    return (REPO_ROOT / document).read_text(encoding="utf-8")


@pytest.mark.parametrize("claim", CLAIMS, ids=lambda c: f"{Path(c.document).name}:{c.means}")
def test_a_registered_claim_is_still_made(claim: Claim) -> None:
    """A registry entry whose sentence is gone describes nothing; remove it."""
    assert claim.phrase in _text(claim.document), (
        f"{claim.document} no longer says {claim.phrase!r}. Remove the entry from "
        "CLAIMS, or restore the sentence if it was lost by accident."
    )


@pytest.mark.parametrize("claim", CLAIMS, ids=lambda c: f"{Path(c.document).name}:{c.means}")
def test_a_registered_claim_is_still_true(claim: Claim) -> None:
    """When the capability arrives, the sentence claiming its absence must change."""
    if claim.phrase not in _text(claim.document):
        pytest.fail(f"{claim.document} no longer makes this claim; see the test above")
    assert claim.holds(), (
        f"{claim.document} says {claim.phrase!r} — {claim.means} — and the code no "
        "longer agrees. Rewrite the sentence from what the code now does, then "
        "update or remove this entry (ADR 0059)."
    )


def test_no_document_dates_itself_by_phase() -> None:
    """A phase label has no runtime source (ADR 0048); "as it stands at P14" drifted four phases."""
    import re

    for document in ("README.md", "docs/architecture.md", "docs/SOURCING_BACKLOG.md"):
        # A quotation of the old sentence, in a note recording its removal, is
        # not the document dating itself.
        found = re.search(r'(?<!")as it stands at P\d+', _text(document))
        assert found is None, f"{document} dates itself: {found.group(0)!r}"
