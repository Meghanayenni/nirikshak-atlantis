"""Corpus policy — decision R9, enforced mechanically rather than remembered.

An evaluation is only worth its separation guarantees. These tests make the
separation a property of the repository instead of a promise in a document:

  * every corpus file is accounted for, with a matching checksum
  * no file appears in two splits
  * vendor packs are authored from `dev` only
  * the held-out vendor has no pack and no seed example
  * nothing in the corpus is represented as real-world data
  * sanitisation is checked, not asserted
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest
import yaml

from api.ingest.packs import load_active_packs

REPO_ROOT = Path(__file__).resolve().parents[2]
CORPUS = REPO_ROOT / "corpus"
MANIFEST_PATH = CORPUS / "MANIFEST.yaml"


@pytest.fixture(scope="module")
def manifest() -> dict:
    return yaml.safe_load(MANIFEST_PATH.read_text(encoding="utf-8"))


def corpus_files() -> list[Path]:
    """Everything under `corpus/` that carries configuration-derived text.

    Includes the label files: they quote lines verbatim out of the
    configurations, so they are held to the same sanitisation standard. A
    credential laundered through a citation is still a credential in the
    repository.
    """
    return sorted(
        p
        for p in CORPUS.rglob("*")
        if p.is_file() and p.name not in ("MANIFEST.yaml", "PROVENANCE.md", ".gitkeep")
    )


def configuration_files() -> list[Path]:
    """The device configurations the manifest tracks.

    Labels and seed examples are excluded because they are derived material
    *about* configurations rather than configurations. They are not manifest
    entries — a label recording its own checksum would be circular — and their
    integrity is enforced instead by binding each to the checksum the manifest
    already records for the file it describes, checked in
    `test_every_label_cites_the_checksum_the_manifest_records`.

    Both remain inside every sanitisation scan above, because both quote
    configuration lines verbatim.
    """
    # PROVENANCE.md is prose ABOUT the configurations, like the manifest itself:
    # it is not a configuration, carries no device data, and a manifest entry for
    # it would be as circular as one for a label.
    derived = {"labels", "seed_examples"}
    return [p for p in corpus_files() if not (derived & set(p.relative_to(CORPUS).parts))]


# ---------------------------------------------------------------------------
# Manifest completeness and integrity
# ---------------------------------------------------------------------------


def test_manifest_exists_and_parses(manifest: dict) -> None:
    assert manifest["files"], "the manifest lists no files"
    assert manifest["held_out_vendor"] == "paloalto"


def test_every_corpus_file_is_in_the_manifest(manifest: dict) -> None:
    """An unlisted file could quietly enter a metric."""
    listed = {entry["path"] for entry in manifest["files"]}
    actual = {p.relative_to(CORPUS).as_posix() for p in configuration_files()}
    assert actual == listed, f"unlisted: {actual - listed}; missing: {listed - actual}"


def test_every_checksum_matches(manifest: dict) -> None:
    """A file edited after labelling would silently invalidate its labels."""
    for entry in manifest["files"]:
        path = CORPUS / entry["path"]
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        assert digest == entry["sha256"], f"{entry['path']} has changed since it was recorded"


def test_no_file_is_in_two_splits(manifest: dict) -> None:
    """Training and evaluating on the same bytes measures memorisation."""
    seen: dict[str, str] = {}
    for entry in manifest["files"]:
        assert entry["path"] not in seen, f"{entry['path']} listed twice"
        seen[entry["path"]] = entry["split"]
    assert set(seen.values()) <= {"dev", "eval", "holdout"}


def test_split_directory_matches_declared_split(manifest: dict) -> None:
    """The directory layout and the manifest must agree."""
    for entry in manifest["files"]:
        parts = Path(entry["path"]).parts
        if entry["split"] == "holdout":
            assert parts[0] == "holdout", f"{entry['path']} is holdout but not under holdout/"
        else:
            assert parts[1] == entry["split"], (
                f"{entry['path']} is declared {entry['split']} but sits under {parts[1]}/"
            )


# ---------------------------------------------------------------------------
# Provenance honesty
# ---------------------------------------------------------------------------


def test_nothing_is_represented_as_real_world_data(manifest: dict) -> None:
    """Synthetic data must never be presented as captured from a real network."""
    for entry in manifest["files"]:
        assert entry["is_real_world_data"] is False
        assert entry["source_type"] == "synthetic"


def test_every_file_records_its_provenance(manifest: dict) -> None:
    required = {
        "path",
        "split",
        "vendor",
        "os_family",
        "source_type",
        "source_ref",
        "authored_by",
        "sanitised",
        "is_real_world_data",
        "sha256",
        "added",
    }
    for entry in manifest["files"]:
        missing = required - set(entry)
        assert not missing, f"{entry['path']} lacks {sorted(missing)}"


def test_manifest_states_the_synthetic_caveat() -> None:
    """The P9 report inherits this wording; it must exist to be inherited."""
    text = MANIFEST_PATH.read_text(encoding="utf-8")
    assert "SYNTHETIC" in text
    assert "must not claim universal vendor coverage" in text


# ---------------------------------------------------------------------------
# Sanitisation, checked rather than promised
# ---------------------------------------------------------------------------

CREDENTIAL_PATTERNS = [
    re.compile(r"password\s+7\s+[0-9A-Fa-f]{4,}"),
    re.compile(r"secret\s+5\s+\$1\$"),
    re.compile(r"\$6\$[./A-Za-z0-9]{8,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    # Any crypt-style value whose salt is not the corpus placeholder (ADR 0055).
    # The two patterns above spoke Cisco type 5 and `$6$`, and the `$6$` one
    # admitted `$6$SAMPLE$…` only because SAMPLE is six characters and the
    # quantifier wants eight — an accident doing the work of a rule. Cisco
    # type 8 and type 9 were not recognised at all, though the Cisco corpus
    # writes `secret 9`, and `$9$` is also JunOS's *reversible* encoding. Every hash-shaped
    # value in the corpus is `$N$SAMPLE$…`; that convention is now the rule.
    re.compile(r"\$(?:1|5|6|8|9)\$(?!SAMPLE\$)[^\s\"';]{4,}"),
]
"""Credential shapes found by pattern. SNMP communities are not here — see below."""


# ---------------------------------------------------------------------------
# SNMP communities: a gate that fails closed (ADR 0055)
# ---------------------------------------------------------------------------
#
# D66 declared a non-default community string a credential. The gate that
# enforced it was a list of vendor SHAPES: IOS `snmp-server community X`, and
# after ADR 0050 JunOS `community X {`. A shape nobody listed — JunOS
# `set snmp community X …`, or `community X;` with no body — matched nothing
# and therefore PASSED. A parser that cannot read a vendor produces UNKNOWN; a
# sanitisation check that cannot read one produced a pass.
#
# So the question is turned round. Every non-comment line that mentions
# `community` must be READ by one of these forms, and a line the gate cannot
# read fails. Teaching the gate a new vendor is then a deliberate edit here,
# forced by a red build, rather than a gap discovered after a secret shipped.

COMMUNITY_FORMS: tuple[re.Pattern[str], ...] = (
    # IOS, IOS XE, NX-OS and EOS: `snmp-server community NAME [ro|rw|group …]`.
    re.compile(r"\bsnmp-server\s+community\s+\"?([^\s\"]+)"),
    # JunOS flat form: `set snmp community NAME …`.
    re.compile(r"^\s*set\s+snmp\s+community\s+\"?([^\s\";]+)"),
    # JunOS brace form: `community NAME {` or `community NAME;`.
    re.compile(r"^\s*community\s+\"?([^\s\";{]+)\"?\s*[{;]"),
)

DEFAULT_COMMUNITIES = frozenset({"public", "private"})
"""Not secrets: the defaults an audit exists to flag, kept in the corpus on purpose."""

COMMENT_OPENERS = ("!", "#", "/*", "*", "//")
"""Line openers across the corpus vendors. Prose in a comment may say "community"."""


def community_problems(text: str, *, configuration: bool = True) -> list[str]:
    """Every community line that is a credential, or that the gate cannot read.

    A readable form anywhere — comments and label prose included — must name a
    default: a secret in a comment is still a secret in the repository. In a
    **configuration** file, a non-comment line mentioning `community` that no
    form reads is a failure in its own right. Label files are YAML whose prose
    discusses community strings in English; they are held to the first rule,
    not the second, because a sentence is not a configuration form.
    """
    problems: list[str] = []
    for number, line in enumerate(text.split("\n"), start=1):
        if "community" not in line.lower():
            continue
        names = [m.group(1) for form in COMMUNITY_FORMS if (m := form.search(line))]
        for name in names:
            if name.strip("\"'").lower() not in DEFAULT_COMMUNITIES:
                problems.append(f"line {number}: non-default SNMP community {name!r}")
        if configuration and not names and not line.lstrip().startswith(COMMENT_OPENERS):
            problems.append(
                f"line {number}: mentions 'community' in a form this gate cannot read — "
                f"teach COMMUNITY_FORMS the form, or it passes unread: {line.strip()!r}"
            )
    return problems


@pytest.mark.parametrize("path", corpus_files(), ids=lambda p: p.name)
def test_no_snmp_community_is_a_credential_or_unread(path: Path) -> None:
    text = path.read_text(encoding="utf-8", errors="replace")
    assert community_problems(text, configuration=path.suffix in (".cfg", ".conf")) == []


@pytest.mark.parametrize(
    ("line", "flagged"),
    [
        ("snmp-server community S3cret RO", True),  # IOS
        ("snmp-server community S3cret group network-operator", True),  # NX-OS
        ("snmp-server community public ro", False),  # EOS, default
        ("set snmp community S3cret authorization read-only", True),  # JunOS flat
        ('set snmp community "public" authorization read-only', False),
        ("    community S3cret {", True),  # JunOS brace, with a body
        ("    community S3cret;", True),  # JunOS brace, no body — was invisible
        ("    community public {", False),
        ("! snmp-server community S3cret RO", True),  # commented out, still a secret
        ("!   and community references.", False),  # prose in a comment
        (" *   is community-based only.", False),  # prose in a JunOS comment block
        ("snmp community-string S3cret", True),  # a shape nobody taught: unread
        ("set policy-options community TRANSIT members 65000:100", True),  # unread, too
    ],
)
def test_the_community_gate_reads_every_vendor_and_fails_closed(line: str, flagged: bool) -> None:
    """The gate's own truth table. The last two are the point: unread is a failure.

    `set policy-options community …` is a BGP community, not a credential, and
    the gate still refuses it — because it cannot tell, and a gate that cannot
    tell must not pass. When a corpus file needs one, the form is added here,
    as a named not-a-credential case.
    """
    assert bool(community_problems(line)) is flagged


def test_label_prose_is_checked_for_secrets_but_not_parsed_as_configuration() -> None:
    prose = "A v1/v2c community string is configured, so SNMP is not v3-only."
    assert community_problems(prose, configuration=False) == []
    assert community_problems("quoted: snmp-server community S3cret RO", configuration=False)


@pytest.mark.parametrize(
    ("value", "flagged"),
    [
        ("enable secret 9 $9$SAMPLE$PlaceholderNotReal", False),
        ("enable secret 9 $9$nhEmQVczB7dqsO$X.HsgL6x1il0RxkOSSvyQYwucySCt7qFm4v7pqCxkKM", True),
        ("enable secret 8 $8$dsYGNam3K1SIJO$7nv/35M/qr6t.dVc7UY9zrJDWRVqncHub1PE9UlMQFs", True),
        ('encrypted-password "$6$SAMPLE$PlaceholderRootHash";', False),
        ('encrypted-password "$6$abcdefgh$realLookingHashValue";', True),
        ('authentication-key "$9$dkflsjfDFLKSJ3kd";', True),  # JunOS reversible
        ("username admin secret 5 $5$SAMPLE$Placeholder", False),
    ],
)
def test_the_hash_gate_speaks_every_crypt_form(value: str, flagged: bool) -> None:
    hit = any(p.search(value) for p in CREDENTIAL_PATTERNS)
    assert hit is flagged


RESERVED_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.", "10.", "172.16.", "192.168.")
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@pytest.mark.parametrize("path", corpus_files(), ids=lambda p: p.name)
def test_no_credentials_in_the_corpus(path: Path) -> None:
    """Hashed credentials are still credentials — a type-7 hash is crackable."""
    text = path.read_text(encoding="utf-8", errors="replace")
    for pattern in CREDENTIAL_PATTERNS:
        assert not pattern.search(text), f"{path.name} contains {pattern.pattern!r}"


@pytest.mark.parametrize("path", corpus_files(), ids=lambda p: p.name)
def test_only_documentation_addressing(path: Path) -> None:
    """RFC 5737 and RFC 1918 only — no real routable addresses."""
    text = path.read_text(encoding="utf-8", errors="replace")
    for address in IPV4.findall(text):
        if address.startswith(("0.", "255.")) or address.endswith(".0") or "255.255" in address:
            continue  # masks and wildcards
        assert address.startswith(RESERVED_PREFIXES), (
            f"{path.name} contains non-documentation address {address}"
        )


RESERVED_DOMAINS = (
    # RFC 2606 §2 — reserved TLDs.
    ".test",
    ".example",
    ".invalid",
    ".localhost",
    # RFC 2606 §3 — reserved second-level names. All THREE are reserved; the
    # allowlist previously named only example.com, so a corpus file using the
    # equally-reserved example.net failed a check it actually satisfied.
    "example.com",
    "example.net",
    "example.org",
)


@pytest.mark.parametrize("path", corpus_files(), ids=lambda p: p.name)
def test_hostnames_use_reserved_domains(path: Path) -> None:
    """RFC 2606 — a documentation domain can never resolve to a real host."""
    text = path.read_text(encoding="utf-8", errors="replace")
    domains = re.findall(r"domain[- ]name[> ]+([A-Za-z0-9.-]+)", text)
    for domain in domains:
        assert domain.endswith(RESERVED_DOMAINS), f"{path.name} uses non-reserved domain {domain}"


# ---------------------------------------------------------------------------
# Train / evaluation separation
# ---------------------------------------------------------------------------


def _pack_examples() -> list[tuple[str, str, str]]:
    """(pack_id, source_id, example) for every literal example a pack declares."""
    out: list[tuple[str, str, str]] = []
    for pack in load_active_packs(use_cache=False):
        for pattern in pack.patterns:
            out += [(pack.pack_id, pattern.id, ex) for ex in pattern.examples]
        for identity in pack.identity:
            out += [(pack.pack_id, f"identity:{identity.field}", ex) for ex in identity.examples]
        # P16 — structure extraction declares examples too, and the same
        # provenance rule applies: an example is the evidence the declaration
        # was authored from, so it must be a line someone actually read in a
        # development file.
        if pack.acl_extraction is not None:
            out += [(pack.pack_id, "acl_extraction", ex) for ex in pack.acl_extraction.examples]
        if pack.interface_extraction is not None:
            out += [
                (pack.pack_id, "interface_extraction", ex)
                for ex in pack.interface_extraction.examples
            ]
    return out


def _lines_in_split(manifest: dict, *splits: str) -> set[str]:
    lines: set[str] = set()
    for entry in manifest["files"]:
        if entry["split"] in splits:
            text = (CORPUS / entry["path"]).read_text(encoding="utf-8", errors="replace")
            lines |= {ln.strip() for ln in text.splitlines() if ln.strip()}
    return lines


def test_every_pack_example_comes_from_the_development_split(manifest: dict) -> None:
    """The rule that keeps a pattern honest.

    An example is the evidence a pattern was authored from. Requiring every one
    to appear verbatim in a development file catches two different failures with
    one check:

      * an example found only in eval or holdout means the pattern was authored
        from data reserved for measuring it — memorisation dressed as accuracy;
      * an example found nowhere at all means the pattern was written from
        general vendor knowledge and verified against nothing.

    The second is not hypothetical. It caught five invented Cisco patterns at P4.
    """
    dev_lines = _lines_in_split(manifest, "dev")

    violations = [
        f"{pack_id} {source_id}: {example!r} appears in no development file"
        for pack_id, source_id, example in _pack_examples()
        if example.strip() not in dev_lines
    ]

    assert not violations, (
        "every pattern example must be a line someone actually read in "
        "corpus/*/dev/:\n" + "\n".join(violations)
    )


def test_no_example_is_unique_to_a_protected_file(manifest: dict) -> None:
    """The original check, kept explicit for the message it gives.

    Subsumed by the test above, but stated separately so a failure says
    'authored from evaluation data' rather than the more general
    'not found in development data'.
    """
    dev_lines = _lines_in_split(manifest, "dev")
    protected_lines = _lines_in_split(manifest, "eval", "holdout")

    violations = [
        f"{pack_id} {source_id}: {example!r} appears only in eval/holdout"
        for pack_id, source_id, example in _pack_examples()
        if example.strip() in protected_lines and example.strip() not in dev_lines
    ]

    assert not violations, "packs were authored from protected files:\n" + "\n".join(violations)


def test_pack_examples_exist_at_all() -> None:
    """Guard against both tests above passing because no pack declares examples."""
    assert len(_pack_examples()) >= 15


# ---------------------------------------------------------------------------
# Platform knowledge provenance (decision D11)
# ---------------------------------------------------------------------------


def _platform_claims() -> list[tuple[str, str, object]]:
    """(pack_id, field, provenance) for every default and capability claim shipped."""
    out: list[tuple[str, str, object]] = []
    for pack in load_active_packs(use_cache=False):
        out += [(pack.pack_id, d.field, d.provenance) for d in pack.defaults]
        out += [
            (pack.pack_id, c.field, c.provenance)
            for c in pack.capabilities
            if c.provenance is not None
        ]
    return out


def test_the_synthetic_corpus_is_never_cited_for_a_platform_default() -> None:
    """A platform default is a claim about the PLATFORM, not about a device.

    Every corpus file is synthetic — written by the team to be realistic, not
    captured from a real network — so no corpus file can establish what a vendor
    documents as its default. Citing one would dress a fixture up as vendor
    documentation, which is the most convincing way this system could be wrong.
    """
    corpus_markers = ("corpus/", ".cfg", ".conf", "rtr-core", "sw-access", "sw-leaf", "srx-")

    violations = [
        f"{pack_id} default for {field!r} cites {marker!r} — a synthetic corpus file"
        for pack_id, field, prov in _platform_claims()
        for marker in corpus_markers
        if marker in f"{getattr(prov, 'source_id', '')} {getattr(prov, 'locator', '')}".lower()
    ]

    assert not violations, "\n".join(violations)


def test_every_sourced_platform_claim_is_actually_findable() -> None:
    """D11 — a 'sourced' claim names a document and a place inside it.

    The contract enforces this at construction. Asserting it again over the
    shipped packs is what catches a default added later with a plausible-looking
    but empty citation.
    """
    from api.models.enums import ProvenanceStatus

    violations = [
        f"{pack_id} claim for {field!r}: sourced but names {prov.source_id!r} / {prov.locator!r}"
        for pack_id, field, prov in _platform_claims()
        if prov.status is ProvenanceStatus.SOURCED
        and not (prov.source_id.strip() and prov.locator.strip())
    ]

    assert not violations, "\n".join(violations)


def test_project_asserted_claims_are_labelled_as_such() -> None:
    """An assertion must never be presented as externally verified."""
    from api.models.enums import PlatformSourceType, ProvenanceStatus

    violations = [
        f"{pack_id} claim for {field!r} mixes assertion and sourcing"
        for pack_id, field, prov in _platform_claims()
        if (prov.source_type is PlatformSourceType.PROJECT_ASSERTED)
        != (prov.status is ProvenanceStatus.PROJECT_ASSERTED)
    ]

    assert not violations, "\n".join(violations)


def test_no_platform_defaults_are_shipped_yet() -> None:
    """P5 ships the absence engine with no authored defaults, deliberately.

    No vendor documentation has been sourced, and the corpus cannot substitute
    for it. Rather than manufacture defaults to make the pipeline look complete,
    every absent field abstains — see ADR 0012 and CORPUS_PREREQUISITES.

    **This test is expected to be deleted** by the change that authors the first
    genuinely sourced default. It fails loudly at that point so the author has to
    look at the provenance tests above rather than adding data quietly.
    """
    packs = load_active_packs(use_cache=False)
    declared = {p.pack_id: (len(p.defaults), len(p.capabilities)) for p in packs}

    assert all(counts == (0, 0) for counts in declared.values()), (
        f"platform knowledge appeared without a sourcing review: {declared}"
    )


def test_held_out_vendor_has_no_pack(manifest: dict) -> None:
    """The generalisation experiment is only real if nothing was ever authored."""
    held_out = manifest["held_out_vendor"]
    packs = load_active_packs(use_cache=False)

    assert all(p.vendor != held_out for p in packs), f"a pack exists for {held_out}"

    pack_files = list((REPO_ROOT / "packs").rglob("*.yaml"))
    for path in pack_files:
        assert held_out not in path.read_text(encoding="utf-8").lower(), (
            f"{path.name} mentions the held-out vendor"
        )


def test_held_out_vendor_files_are_all_in_holdout(manifest: dict) -> None:
    held_out = manifest["held_out_vendor"]
    for entry in manifest["files"]:
        if entry["vendor"] == held_out:
            assert entry["split"] == "holdout", (
                f"{entry['path']} is {held_out} but not in the holdout split"
            )


def test_holdout_contains_only_the_held_out_vendor(manifest: dict) -> None:
    held_out = manifest["held_out_vendor"]
    for entry in manifest["files"]:
        if entry["split"] == "holdout":
            assert entry["vendor"] == held_out


def test_corpus_has_the_four_planned_vendors(manifest: dict) -> None:
    vendors = {e["vendor"] for e in manifest["files"]}
    assert vendors == {"cisco", "arista", "juniper", "paloalto"}


def test_ios_and_arista_are_both_present(manifest: dict) -> None:
    """Kept deliberately: their similarity is what tests the ambiguity rule."""
    dev = {e["vendor"] for e in manifest["files"] if e["split"] == "dev"}
    assert {"cisco", "arista"} <= dev


def test_every_split_has_files(manifest: dict) -> None:
    from collections import Counter

    counts = Counter(e["split"] for e in manifest["files"])
    assert counts["dev"] >= 4
    assert counts["eval"] >= 2
    assert counts["holdout"] >= 1


# ---------------------------------------------------------------------------
# Ground truth (P9, defect DEF-6)
#
# The `labelled` flag was set on five files from the day the corpus was
# committed, and `corpus/labels/` held nothing but a `.gitkeep`. Nothing read
# the flag, so the manifest asserted a property the repository did not have for
# three phases. These tests are what stop it drifting again.
# ---------------------------------------------------------------------------


def test_the_labelled_flag_matches_the_filesystem(manifest: dict) -> None:
    """DEF-6 — a flag nothing checks eventually describes a previous release."""
    labels_root = CORPUS / "labels"
    labelled_paths = set()
    for path in sorted(labels_root.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        labelled_paths.add(data["corpus_path"])

    for entry in manifest["files"]:
        declared = entry.get("labelled", False)
        actual = entry["path"] in labelled_paths
        assert declared == actual, (
            f"{entry['path']} declares labelled={declared} but "
            f"{'has' if actual else 'has no'} label file under corpus/labels/"
        )


def test_only_evaluation_files_are_labelled(manifest: dict) -> None:
    """Ground truth beside the files patterns are authored from is an invitation.

    And the held-out vendor may not be labelled at all: labelling requires
    reading, and nothing may read it until the generalisation experiment.
    """
    for entry in manifest["files"]:
        if entry.get("labelled"):
            assert entry["split"] == "eval", (
                f"{entry['path']} is labelled but sits in the {entry['split']} split"
            )


def test_no_label_file_mentions_the_held_out_vendor(manifest: dict) -> None:
    held_out = manifest["held_out_vendor"]
    for path in sorted((CORPUS / "labels").glob("*.yaml")):
        text = path.read_text(encoding="utf-8").lower()
        assert held_out not in text, f"{path.name} names the held-out vendor"
        assert "holdout" not in text, f"{path.name} names the holdout split"


def test_every_label_cites_the_checksum_the_manifest_records(manifest: dict) -> None:
    """A label bound to different bytes than the manifest lists is scoring a
    file nobody can identify."""
    by_path = {e["path"]: e for e in manifest["files"]}

    for path in sorted((CORPUS / "labels").glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        entry = by_path[data["corpus_path"]]
        assert data["file_sha256"] == entry["sha256"], (
            f"{path.name} was written against a different version of "
            f"{data['corpus_path']} than the manifest records"
        )


def test_no_label_was_authored_from_pipeline_output() -> None:
    """ADR 0010 — a label is authored from the configuration, never from output.

    Checked as a property of the recorded provenance: `authored_from` must name
    the raw configuration, and no label may claim to have read a report, a
    finding or a parse result.
    """
    forbidden = ("finding", "report", "parsed", "csm", "canonical model", "audit")

    for path in sorted((CORPUS / "labels").glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        source = str(data["provenance"]["authored_from"]).lower()

        assert data["corpus_path"] in source, (
            f"{path.name} does not record reading its own configuration"
        )
        for token in forbidden:
            assert token not in source, f"{path.name} was authored from {token!r}"
