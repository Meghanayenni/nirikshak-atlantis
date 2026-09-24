"""Each index is re-derivable from the document it names — where that document is.

ADR 0035 left one gap stated plainly: the NIST catalog is not in the tree, so the
index is *trusted* until somebody re-derives it. ADR 0052 adds two frameworks
whose source documents sit on opposite sides of that line:

  * the DISA STIG XCCDF **is** committed, so its index is **verified on every
    run** — hash the held file, re-read it, compare;
  * the CIS Benchmark **may never** be committed, so its index is verified only
    where an operator supplies the file (`NIRIKSHAK_CIS_BENCHMARK`), and is
    trusted everywhere else, exactly as NIST is.

One framework content-addressed *in* the repository; one only *by* it.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from api.comply.frameworks import Coverage, indexes
from api.models.enums import Framework
from scripts.fetch_framework_catalog import read_cis_pdf, read_stig_xccdf

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

CIS_SOURCE = os.environ.get("NIRIKSHAK_CIS_BENCHMARK", "")
HAVE_CIS_SOURCE = bool(CIS_SOURCE) and Path(CIS_SOURCE).is_file()


@pytest.fixture(scope="module")
def stig():
    return indexes()[Framework.STIG]


@pytest.fixture(scope="module")
def cis():
    return indexes()[Framework.CIS]


# ---------------------------------------------------------------------------
# STIG — held, so verified here, always
# ---------------------------------------------------------------------------


def test_the_held_stig_is_the_file_the_index_names(stig) -> None:
    held = REPO_ROOT / stig.held_at
    assert held.is_file(), f"{stig.held_at} is named by the index and missing"
    assert hashlib.sha256(held.read_bytes()).hexdigest() == stig.sha256


def test_the_stig_index_re_derives_from_the_held_file(stig) -> None:
    """Not trusted: recomputed. Every identifier and the edition, from the bytes."""
    edition, live, withdrawn = read_stig_xccdf(REPO_ROOT / stig.held_at)

    assert edition == stig.edition == "V3R7 (2026-04-01)"
    assert all(stig.knows(i) for i in live)
    assert stig.control_count == len(live) == 42
    assert withdrawn == []


def test_the_stig_identifier_is_the_stig_id_not_the_rule_revision(stig) -> None:
    """`CISC-ND-000470` is what an assessor cites; `SV-…r…_rule` changes every release."""
    assert stig.knows("CISC-ND-000470")
    assert not stig.knows("SV-215823r1043177_rule")
    assert not stig.knows("V-215823")


# ---------------------------------------------------------------------------
# CIS — referenced, so verified only where an operator supplies it
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAVE_CIS_SOURCE, reason="NIRIKSHAK_CIS_BENCHMARK names no file")
def test_the_cis_index_re_derives_from_the_operator_supplied_file(cis) -> None:
    """Run with NIRIKSHAK_CIS_BENCHMARK=/outside/the/tree/benchmark.pdf.

    The file must be outside the repository; the architecture suite fails if a
    copy is found inside it.
    """
    path = Path(CIS_SOURCE)
    assert not path.resolve().is_relative_to(REPO_ROOT)
    assert hashlib.sha256(path.read_bytes()).hexdigest() == cis.sha256

    edition, live, _ = read_cis_pdf(path)
    assert edition == cis.edition == "v2.2.1 (2025-07-17)"
    assert all(cis.knows(n) for n in live) and cis.control_count == len(live)


@pytest.mark.skipif(HAVE_CIS_SOURCE, reason="the operator-supplied file is verified above")
def test_without_the_file_the_cis_index_says_it_is_trusted_not_verified(cis) -> None:
    """The honest state on every checkout, CI included: pinned, not re-derived.

    The index must say where the material is — nowhere in this tree — so a
    reader does not mistake a digest for a document they can open.
    """
    assert not cis.held_at and not cis.source_url
    assert "Referenced, not held" in cis.source_note
    assert len(cis.sha256) == 64


# ---------------------------------------------------------------------------
# Coverage — an edition speaks about one platform
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("framework", [Framework.STIG, Framework.CIS])
def test_a_platform_benchmark_covers_ios_xe_17_only(framework: Framework) -> None:
    index = indexes()[framework]
    assert index.coverage("cisco", "ios", "17.9") is Coverage.COVERED
    assert index.coverage("cisco", "ios", "15.2") is Coverage.NOT_COVERED, "classic IOS"
    assert index.coverage("cisco", "nxos", "9.3(6)") is Coverage.NOT_COVERED
    assert index.coverage("juniper", "junos", "21.4R3") is Coverage.NOT_COVERED
    assert index.coverage("cisco", "ios", None) is Coverage.UNDETERMINABLE


def test_nist_declares_no_platform_and_covers_everything() -> None:
    nist = indexes()[Framework.NIST]
    assert nist.covers is None
    assert nist.coverage("juniper", "junos", None) is Coverage.COVERED
