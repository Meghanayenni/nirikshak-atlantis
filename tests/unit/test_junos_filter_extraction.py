"""JunOS firewall filters in flat `set` form, read from a development file.

26 ACL lines sat in residue across three JunOS files because no pack declared
extraction for the dialect. This module covers the 15 of them that make up
`corpus/juniper/dev/edge-rtr-02.conf`'s one filter, plus the arithmetic that
reads them.

**What is deliberately not covered here**, because nothing can exercise it: the
brace-nested form of the same filters. `corpus/juniper/dev/core-rtr-01.conf` is
legitimate JunOS and vendor detection does not identify it — it scores 0.25 as
`cisco/ios`, below the threshold — so a file in that form never reaches a pack
at all. `test_the_brace_nested_form_is_still_unreachable` pins that, and is
expected to fail when somebody fixes detection, which is when the second reader
becomes worth writing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from api.analyse.service import analyse_device
from api.config import settings
from api.ingest.packs import find_pack, load_active_packs
from api.ingest.vendor_detect import detect_vendor
from api.models.enums import AclDialect, AclObservationKind, AddrKind
from api.models.ingestion import DetectionOutcome
from api.normalise.service import build_csm
from api.parse.service import parse_configuration

DEV = Path("corpus/juniper/dev")
FLAT = DEV / "edge-rtr-02.conf"
BRACE = DEV / "core-rtr-01.conf"


@pytest.fixture(scope="module")
def packs():
    return load_active_packs(use_cache=False)


@pytest.fixture(scope="module")
def junos(packs):
    return find_pack("juniper", "junos", packs)


@pytest.fixture(scope="module")
def csm(junos):
    parsed = parse_configuration(
        FLAT.read_text(encoding="utf-8"), junos, file_id=FLAT.name, file_path=str(FLAT)
    )
    return build_csm(parsed, junos, device_id=FLAT.name)


# ---------------------------------------------------------------------------
# The declaration
# ---------------------------------------------------------------------------


def test_the_pack_declares_the_set_form_dialect(junos) -> None:
    assert junos.acl_extraction is not None
    assert junos.acl_extraction.dialect is AclDialect.JUNOS_SET_FILTER


def test_the_pack_declares_no_binding_syntax(junos) -> None:
    """`applied` is null, and that is a statement rather than an omission.

    A filter's binding is read off an interface, and this pack declares no
    interface extraction — so there is nothing for a binding regex to be matched
    against. Declaring one anyway would put a regex in the pack that nothing
    runs, which is how DEF-12 happened.
    """
    assert junos.acl_extraction.applied is None
    assert junos.interface_extraction is None


# ---------------------------------------------------------------------------
# The filter
# ---------------------------------------------------------------------------


def test_one_filter_is_read_whole(csm) -> None:
    assert [acl.name for acl in csm.acls] == ["PROTECT-RE"]
    assert csm.acl_failures == ()
    assert len(csm.acls[0].entries) == 4


def test_terms_keep_the_order_the_device_evaluates_them_in(csm) -> None:
    """One term is several lines, so grouping had to choose an order.

    First appearance, because that is the order JunOS evaluates terms in and
    order is the whole of shadowing analysis. A dictionary iteration order or a
    sort by name would both be wrong, and wrong invisibly.
    """
    entries = csm.acls[0].entries
    assert [e.seq for e in entries] == [1, 2, 3, 4]
    assert [e.evidence[0].line_start for e in entries] == [65, 69, 73, 77]


def test_a_term_cites_every_line_that_built_it(csm) -> None:
    """Rule 2 over a multi-line entry.

    `allow-mgmt-ssh` is four lines — three `from` clauses and one `then`. An
    operator changing it needs all four, not the first.
    """
    first = csm.acls[0].entries[0]
    assert [e.line_start for e in first.evidence] == [65, 66, 67, 68]
    assert first.evidence[-1].raw_line.strip().endswith("then accept")


def test_a_term_with_no_from_clause_matches_everything(csm) -> None:
    """`log-and-deny` states only actions, so it is the catch-all deny."""
    last = csm.acls[0].entries[3]
    assert last.action.value == "deny"
    assert last.src.is_any and last.dst.is_any
    assert last.protocol.is_any
    assert last.dst_port.is_any
    assert last.flags.log, "`then log` and `then syslog` both set the log flag"


def test_named_ports_resolve_to_their_numbers(csm) -> None:
    ssh, https = csm.acls[0].entries[0], csm.acls[0].entries[1]
    assert (ssh.dst_port.low, ssh.dst_port.high) == (22, 22)
    assert (https.dst_port.low, https.dst_port.high) == (443, 443)


def test_a_prefix_list_resolves_from_its_definition_in_the_same_file(csm) -> None:
    """`source-prefix-list TRUSTED-MGMT` against `set policy-options prefix-list`.

    Resolved because the configuration defines it, not because a plausible range
    was available. It matters: an unresolved address makes `address_covers`
    return None, and the analyser then reports UNDETERMINED instead of comparing
    — so an unresolved prefix list would discard information the operator gave.
    """
    src = csm.acls[0].entries[0].src
    assert src.kind is AddrKind.OBJECT
    assert src.value == "TRUSTED-MGMT"
    assert src.resolved_cidrs == ("198.51.100.0/24",)


# ---------------------------------------------------------------------------
# What the analyser makes of it
# ---------------------------------------------------------------------------


def test_the_duplicated_term_is_reported_redundant(csm) -> None:
    """`allow-mgmt-https-dup` matches exactly what `allow-mgmt-https` matches.

    The first genuine redundancy found on a parsed access list — the Cisco
    corpus produced one too, but on a list whose catch-all made several entries
    redundant at once. Here the two terms are equal and nothing else is.
    """
    observations = analyse_device(csm).observations

    assert len(observations) == 1
    only = observations[0]
    assert only.kind is AclObservationKind.REDUNDANT
    assert only.acl_id == "PROTECT-RE"
    assert only.entry_seq == 3
    assert only.caused_by == (2,)


def test_nothing_is_called_shadowed_or_overly_permissive(csm) -> None:
    """The converse, stated separately because it is the easier mistake.

    The final `log-and-deny` matches everything, but a *deny* catch-all at the
    bottom is what a filter is supposed to end with. An analyser that flagged it
    would be pattern-matching for alarm.
    """
    kinds = {o.kind for o in analyse_device(csm).observations}
    assert AclObservationKind.SHADOWED not in kinds
    assert AclObservationKind.OVERLY_PERMISSIVE not in kinds


# ---------------------------------------------------------------------------
# Residue
# ---------------------------------------------------------------------------


def test_the_lines_the_reader_consumed_leave_the_training_queue(junos) -> None:
    """Including the prefix list, which is evidence for an entry it resolved."""
    parsed = parse_configuration(
        FLAT.read_text(encoding="utf-8"), junos, file_id=FLAT.name, file_path=str(FLAT)
    )
    remaining = {node.line_number for node in parsed.residue}

    assert not remaining & set(range(64, 80)), (
        "the 15 filter-term lines and the prefix-list definition they resolve "
        "through should all have left residue"
    )


def test_the_interface_binding_is_still_in_residue(junos) -> None:
    """Honest about the half that did not land.

    `set interfaces lo0 unit 0 family inet filter input PROTECT-RE` binds the
    filter, and this pack reads no interfaces — so `PROTECT-RE.applied_to` is
    empty and the line stays in front of a human. That is the correct output for
    a binding nobody can resolve, not an oversight to paper over.
    """
    parsed = parse_configuration(
        FLAT.read_text(encoding="utf-8"), junos, file_id=FLAT.name, file_path=str(FLAT)
    )
    binding = [n for n in parsed.residue if n.text.startswith("set interfaces lo0")]

    assert binding, "the binding line should remain unrecognised"
    csm = build_csm(parsed, junos, device_id=FLAT.name)
    assert csm.acls[0].applied_to == ()


# ---------------------------------------------------------------------------
# The blocker, pinned so that fixing it fails here first
# ---------------------------------------------------------------------------


def test_the_brace_nested_form_is_still_unreachable(packs) -> None:
    """`core-rtr-01.conf` is legitimate JunOS that no pack is selected for.

    ADR 0024 recorded that the juniper signatures match the flat `set` form
    only. That is upstream of extraction: a brace-form reader could be written
    today and nothing would ever call it, so writing one would be a declaration
    no test could show right or wrong — the thing D73 declined to do.

    **This test is expected to fail** when somebody adds brace-form detection
    signatures. That is the moment the second reader becomes worth writing, and
    failing here is how they find out.
    """
    lines = BRACE.read_text(encoding="utf-8").splitlines()
    result = detect_vendor(
        packs,
        lines,
        filename=BRACE.name,
        min_score=settings.detection_min_score,
        min_margin=settings.detection_min_margin,
    )

    assert result.outcome is not DetectionOutcome.DETECTED
    assert all(c.vendor != "juniper" for c in result.candidates), (
        "no juniper signature matches a brace-nested file"
    )


# ---------------------------------------------------------------------------
# All-or-nothing, on constructed input
# ---------------------------------------------------------------------------
#
# No JunOS corpus file defeats this reader, so the drop path is exercised here
# rather than against a fixture. That is stated rather than left implicit: a
# branch tested only on constructed input is tested, not demonstrated.

from api.models.enums import AclType  # noqa: E402
from api.models.pack import AclExtraction, VendorPack  # noqa: E402
from api.parse.block_parser import build_tree  # noqa: E402
from api.parse.structures import extract_acls  # noqa: E402

JUNOS_SPEC = AclExtraction(
    dialect=AclDialect.JUNOS_SET_FILTER,
    acl_type=AclType.EXTENDED,
    named_block=r"^set firewall family inet filter (\S+) ",
)


def junos_pack() -> VendorPack:
    return VendorPack(
        vendor="juniper",
        os_family="junos",
        pack_version="9.9.9",
        acl_extraction=JUNOS_SPEC,
    )


def junos_tree(text: str):
    return build_tree(text, file_id="f" * 64, file_path="constructed.conf", comment_prefixes=("#",))


def _filter_line(term: str, clause: str) -> str:
    return f"set firewall family inet filter F term {term} {clause}\n"


def test_a_term_taking_an_action_that_decides_nothing_drops_the_filter() -> None:
    """`then next term` hands the packet to the term below.

    Modelling it as permit or deny would state something about the device that
    is not true, and the entries around it would then be compared against a
    fiction. The whole filter goes, which is D75 applied to a second dialect.
    """
    t = junos_tree(
        _filter_line("a", "from protocol tcp")
        + _filter_line("a", "then next term")
        + _filter_line("b", "then accept")
    )
    acls, failures = extract_acls(t, junos_pack())

    assert acls == ()
    assert len(failures) == 1
    assert failures[0].acl_name == "F"
    assert "'next term'" in failures[0].reason
    assert "does not decide the packet" in failures[0].reason


def test_a_bracketed_port_list_drops_the_filter_and_says_why() -> None:
    """`destination-port [ ssh https ]` is two intervals in one field.

    `PortSpec` holds one. Splitting the term into two entries would invent an
    ordering the configuration does not state, and collapsing it to a range
    would match ports nobody permitted.
    """
    t = junos_tree(
        _filter_line("a", "from destination-port [ ssh https ]") + _filter_line("a", "then accept")
    )
    _, failures = extract_acls(t, junos_pack())

    assert "two intervals" in failures[0].reason


def test_an_unknown_match_condition_names_the_keyword() -> None:
    t = junos_tree(_filter_line("a", "from tcp-flags syn") + _filter_line("a", "then accept"))
    _, failures = extract_acls(t, junos_pack())

    assert "'tcp-flags'" in failures[0].reason
    assert "does not read" in failures[0].reason


def test_a_term_that_only_logs_drops_the_filter() -> None:
    """Logging is not a verdict on the packet."""
    t = junos_tree(_filter_line("a", "then log"))
    acls, failures = extract_acls(t, junos_pack())

    assert acls == ()
    assert "decides nothing on its own" in failures[0].reason


def test_one_unreadable_term_drops_only_its_own_filter() -> None:
    """Two filters, one broken. The other is still emitted."""
    t = junos_tree(
        "set firewall family inet filter GOOD term a then accept\n"
        "set firewall family inet filter BAD term a then next term\n"
    )
    acls, failures = extract_acls(t, junos_pack())

    assert [a.name for a in acls] == ["GOOD"]
    assert [f.acl_name for f in failures] == ["BAD"]


def test_an_unresolvable_prefix_list_is_kept_but_not_placed_on_the_number_line() -> None:
    """Referenced and never defined: the entry survives, the address does not.

    This is the IOS `object-group` case in JunOS clothing. The term is real and
    belongs in the list; what is unknown is which addresses it covers, and the
    analyser reports UNDETERMINED rather than comparing against a guess.
    """
    t = junos_tree(
        _filter_line("a", "from source-prefix-list NEVER-DEFINED")
        + _filter_line("a", "then accept")
    )
    acls, failures = extract_acls(t, junos_pack())

    assert failures == ()
    assert acls[0].entries[0].src.resolved_cidrs == ()
    assert acls[0].entries[0].src.value == "NEVER-DEFINED"
