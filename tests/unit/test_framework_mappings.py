"""Every shipped framework mapping names a real control in a real edition.

This module replaces `test_no_framework_mappings_are_claimed`, which asserted
that **zero** control identifiers ship and was written to be deleted by whoever
sourced the first one. It was deleted by the commit that added these (ADR 0035).

The gate it enforced has not been relaxed, only moved. Before, the rule was *no
identifier may be written without reading the benchmark*. Now it is *every
identifier must exist in a catalog whose bytes are content-addressed, and no
mapping may call itself official*.
"""

from __future__ import annotations

import pytest

from api.comply.frameworks import CatalogIndex, indexes, sourced_frameworks
from api.comply.rulepacks import load_rulepack
from api.models.enums import Framework, MappingProvenance


@pytest.fixture(scope="module")
def rulepack():
    return load_rulepack()


@pytest.fixture(scope="module")
def catalogs() -> dict[Framework, CatalogIndex]:
    return indexes()


def mappings(rulepack):
    return [(rule, ref) for rule in rulepack.rules for ref in rule.frameworks]


# ---------------------------------------------------------------------------
# Something ships, and it is checkable
# ---------------------------------------------------------------------------


def test_mappings_are_shipped_at_all(rulepack) -> None:
    """The replacement for the old empty-state assertion, in the new direction."""
    assert mappings(rulepack), "no rule maps to any framework"
    assert rulepack.frameworks_covered == frozenset({Framework.NIST})


def test_every_rule_is_mapped(rulepack) -> None:
    """A partly-mapped rulepack would report coverage that varies by check."""
    unmapped = [r.rule_id for r in rulepack.rules if not r.frameworks]
    assert unmapped == [], f"rules with no framework mapping: {unmapped}"


def test_every_mapping_carries_a_citation_and_a_catalog_version(rulepack) -> None:
    """The two fields that make a mapping checkable by somebody else.

    A control identifier on its own is unfalsifiable: `AC-17(02)` means nothing
    without the edition it belongs to, because control identifiers are
    *reused across revisions with different meanings* and withdrawn between
    them. The citation says which document, the version says which edition of
    it.
    """
    problems = [
        f"{rule.rule_id} -> {ref.framework.value}:{ref.control_id}"
        for rule, ref in mappings(rulepack)
        if not (ref.citation or "").strip() or not (ref.version or "").strip()
    ]
    assert problems == [], "\n".join(problems)


def test_every_control_id_exists_in_its_catalog(rulepack, catalogs) -> None:
    """The claim the index exists to support.

    Not "this looks like a control identifier" — this identifier is present in
    a catalog whose sha256 is recorded, in the edition the mapping names.
    """
    unknown = []
    for rule, ref in mappings(rulepack):
        index = catalogs.get(ref.framework)
        assert index is not None, (
            f"{rule.rule_id} maps to {ref.framework.value}, which has no sourced catalog"
        )
        if not index.knows(ref.control_id):
            unknown.append(f"{rule.rule_id} -> {ref.framework.value}:{ref.control_id}")
    assert unknown == [], "identifiers absent from the catalog:\n" + "\n".join(unknown)


def test_no_mapping_points_at_a_withdrawn_control(rulepack, catalogs) -> None:
    """The failure this whole apparatus exists to prevent.

    `AC-17(08)` — "Disable Nonsecure Network Protocols" — and `AU-08(01)` —
    "Synchronization with Authoritative Time Source" — are both **withdrawn** in
    Rev 5, and both are exactly what a person would write from memory for
    NIRIKSHAK's telnet and NTP checks. A withdrawn identifier looks entirely
    plausible in a report and is wrong.
    """
    withdrawn = [
        f"{rule.rule_id} -> {ref.control_id}"
        for rule, ref in mappings(rulepack)
        if (index := catalogs.get(ref.framework)) and index.is_withdrawn(ref.control_id)
    ]
    assert withdrawn == [], "\n".join(withdrawn)


def test_the_version_on_every_mapping_matches_its_catalog(rulepack, catalogs) -> None:
    """A citation naming edition 5.2.0 must have been checked against 5.2.0."""
    drift = [
        f"{rule.rule_id} -> {ref.control_id} says {ref.version!r}, "
        f"catalog is {catalogs[ref.framework].edition!r}"
        for rule, ref in mappings(rulepack)
        if ref.framework in catalogs and ref.version != catalogs[ref.framework].edition
    ]
    assert drift == [], "\n".join(drift)


# ---------------------------------------------------------------------------
# Nothing claims to be official
# ---------------------------------------------------------------------------


def test_no_mapping_is_marked_official(rulepack) -> None:
    """**A catalog publishes controls. It does not publish mappings.**

    The OSCAL file says AC-17(02) exists, what it is called and where it sits.
    It says nothing whatever about whether NIRIKSHAK's `NRK-SSH-001` satisfies
    it — that is this project's judgement, and `OFFICIAL` would claim somebody
    else made it.

    `OFFICIAL` is reserved for a mapping taken from a published crosswalk that
    names our check. No such document exists or is likely to, so this assertion
    is expected to hold indefinitely. It is written as a test rather than a
    convention because `project_asserted` is one word away from `official` in a
    YAML file, and the difference is the difference between a citation and a
    claim of endorsement.
    """
    official = [
        f"{rule.rule_id} -> {ref.framework.value}:{ref.control_id}"
        for rule, ref in mappings(rulepack)
        if ref.mapping_provenance is MappingProvenance.OFFICIAL
    ]
    assert official == [], (
        "these mappings claim to come from a published crosswalk:\n" + "\n".join(official)
    )


def test_has_official_mapping_is_false_for_every_rule(rulepack) -> None:
    """The accessor a report would use, checked at its own level."""
    assert not any(rule.has_official_mapping for rule in rulepack.rules)


# ---------------------------------------------------------------------------
# The index itself
# ---------------------------------------------------------------------------


def test_the_index_records_the_catalog_bytes_it_came_from(catalogs) -> None:
    """A version string is a label; a sha256 is the document.

    Two people holding "Rev 5" may hold different files. This is what lets a
    reviewer obtain the catalog themselves and confirm they are checking the
    same one, which costs nothing and is the difference between a citation that
    can be verified and one that must be trusted.
    """
    for index in catalogs.values():
        assert len(index.sha256) == 64
        assert int(index.sha256, 16) >= 0, "sha256 must be hexadecimal"
        assert index.source_url.startswith("https://")


def test_only_frameworks_with_a_catalog_are_offered(catalogs) -> None:
    """A framework with no sourced mapping must be **absent**, not empty.

    An empty result reads as "your fleet is compliant". "We have never read this
    benchmark" is a different statement, and a selector that rendered them the
    same would turn a sourcing gap into a clean bill of health.
    """
    assert sourced_frameworks() == frozenset(catalogs)
    assert Framework.CIS not in sourced_frameworks()
    assert Framework.STIG not in sourced_frameworks()
    assert Framework.ISO not in sourced_frameworks()


def test_the_index_carries_no_control_text(catalogs) -> None:
    """`docs/CONTENT_POLICY.md` — identifiers and locators, never prose.

    Checked on the file rather than on the model: the policy is about what the
    repository accumulates, and a field the loader ignores would still be
    committed.
    """
    import yaml

    from api.comply.frameworks import FRAMEWORK_INDEX_ROOT

    forbidden = {"text", "prose", "statement", "guidance", "title", "titles", "parts"}
    for path in FRAMEWORK_INDEX_ROOT.glob("*.index.yaml"):
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert not (forbidden & set(raw)), f"{path.name} carries control prose"


def test_a_control_absent_from_the_catalog_is_not_known(catalogs) -> None:
    """The index says no to something, or it is not checking anything."""
    nist = catalogs[Framework.NIST]
    assert not nist.knows("AC-99(42)")
    assert not nist.knows("AC-17(2)"), (
        "the catalog's own labels are zero-padded; the unpadded form a person "
        "would type from memory must not validate"
    )
