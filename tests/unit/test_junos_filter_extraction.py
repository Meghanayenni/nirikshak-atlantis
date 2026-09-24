"""JunOS firewall filters, in both surfaces the platform ships.

26 ACL lines sat in residue across three JunOS files because no pack declared
extraction for the dialect. P17 read the flat `set` form —
`corpus/juniper/dev/edge-rtr-02.conf`, one filter over 15 lines. P18 read the
brace-nested form (ADR 0043), which had been unreachable end to end:
`corpus/juniper/dev/core-rtr-01.conf` scored 0.25 as `cisco/ios` and fell below
the detection floor, and behind that sat three further blockers — the syntax
mode was keyed to the platform rather than the file, `SyntaxMode.BRACE` raised,
and the flat reader groups top-level lines where brace terms are subtrees.

`test_the_brace_nested_form_is_still_unreachable` stood here and was written to
fail when somebody fixed detection. It was deleted by the change that earned it.

**The two surfaces are one filter language**, so the tests assert they agree:
the same construct must not expand in one and drop the filter in the other.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from api.analyse.service import analyse_device
from api.config import settings
from api.ingest.device_identity import extract_identity
from api.ingest.packs import find_pack, load_active_packs
from api.ingest.vendor_detect import detect_vendor
from api.models.enums import (
    AclAction,
    AclDialect,
    AclObservationKind,
    AddrKind,
    SyntaxMode,
)
from api.models.ingestion import DetectionOutcome
from api.normalise.service import build_csm
from api.parse.service import parse_configuration, syntax_mode_for

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


def test_the_pack_declares_the_filter_dialect(junos) -> None:
    assert junos.acl_extraction is not None
    assert junos.acl_extraction.dialect is AclDialect.JUNOS_FILTER


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
# The brace surface, which was the blocker
# ---------------------------------------------------------------------------
#
# `test_the_brace_nested_form_is_still_unreachable` stood here. It asserted that
# no pack was selected for `core-rtr-01.conf` and was written to fail when
# somebody added brace-form signatures. It was deleted by the change that earned
# it (ADR 0043), and these replace it.


@pytest.fixture(scope="module")
def brace_csm(junos):
    parsed = parse_configuration(
        BRACE.read_text(encoding="utf-8"), junos, file_id=BRACE.name, file_path=str(BRACE)
    )
    return build_csm(parsed, junos, device_id=BRACE.name)


def test_the_brace_form_is_detected_by_a_margin(packs) -> None:
    """Two surfaces, one pack, and the brace signatures discriminate.

    They must not match an indent-based platform, or the `min_margin` ambiguity
    rule fires and the file becomes unauditable a second way. Each is a
    top-level block name no Cisco or Arista file writes at column zero.
    """
    result = detect_vendor(
        packs,
        BRACE.read_text(encoding="utf-8").splitlines(),
        filename=BRACE.name,
        min_score=settings.detection_min_score,
        min_margin=settings.detection_min_margin,
    )

    assert result.outcome is DetectionOutcome.DETECTED
    assert (result.vendor, result.os_family) == ("juniper", "junos")
    assert result.margin >= settings.detection_min_margin


@pytest.mark.parametrize(
    "path",
    [
        Path("corpus/cisco/dev/rtr-core-01.cfg"),
        Path("corpus/cisco/dev/dc1-leaf-01.cfg"),
        Path("corpus/arista/dev/sw-leaf-01.cfg"),
    ],
)
def test_the_brace_signatures_claim_no_indent_based_platform(packs, path: Path) -> None:
    """The direction that would do damage quietly.

    A brace signature matching an IOS file would not fail on the JunOS file —
    it would start pulling Cisco devices towards the JunOS pack, where every
    pattern misses and every field reads UNKNOWN.
    """
    result = detect_vendor(
        packs,
        path.read_text(encoding="utf-8").splitlines(),
        filename=path.name,
        min_score=settings.detection_min_score,
        min_margin=settings.detection_min_margin,
    )
    junos_score = next(
        (c.score for c in result.candidates if (c.vendor, c.os_family) == ("juniper", "junos")),
        0.0,
    )

    assert junos_score == 0.0, f"a JunOS signature matched {path.name}"


def test_the_surface_is_chosen_from_the_file_not_the_platform(junos) -> None:
    """Both files are `juniper/junos`; they are not the same shape.

    Keying the syntax mode to `os_family` alone meant a brace file would have
    been parsed as flat `set` paths even once detection identified it — 165
    lines read as unrecognised. The surface is a property of the export.
    """
    assert syntax_mode_for(junos, BRACE.read_text(encoding="utf-8")) is SyntaxMode.BRACE
    assert syntax_mode_for(junos, FLAT.read_text(encoding="utf-8")) is SyntaxMode.SET_PATH


def test_the_brace_filter_is_read_whole(brace_csm) -> None:
    """Five terms, six entries — one term carries a two-port list."""
    assert [acl.name for acl in brace_csm.acls] == ["PROTECT-RE"]
    assert brace_csm.acl_failures == ()
    assert len(brace_csm.acls[0].entries) == 6


def test_a_bracketed_port_list_expands_into_adjacent_entries(brace_csm) -> None:
    """`destination-port [ ssh https ]` is one term matching two ports.

    `PortSpec` holds one interval, so the term becomes two entries with the
    same action and everything else equal. They are adjacent, so nothing can
    come between them and the ordering the analysis depends on is preserved.
    """
    entries = brace_csm.acls[0].entries
    ports = [(e.dst_port.low, e.dst_port.high) for e in entries[1:3]]

    assert ports == [(22, 22), (443, 443)]
    assert entries[1].action is entries[2].action
    assert entries[1].src.resolved_cidrs == entries[2].src.resolved_cidrs


def test_a_brace_term_cites_every_line_that_built_it(brace_csm) -> None:
    """Rule 2 over a nested term: the header, the `from`, its conditions, the `then`."""
    entry = brace_csm.acls[0].entries[1]
    cited = {e.line_start for e in entry.evidence}

    assert len(cited) >= 5, f"a five-line term cited only {sorted(cited)}"
    raw = " ".join(e.raw_line for e in entry.evidence)
    assert "term allow-management" in raw
    assert "source-address" in raw


def test_the_catch_all_term_shadows_the_terms_below_it(brace_csm) -> None:
    """The expected result, and the reason this file was worth unblocking.

    `term allow-anything { then accept; }` sits above `block-remote-telnet` and
    `default-deny`, so neither can ever take effect. A filter that reads as
    though it blocks telnet and does not is exactly what the interval analyser
    exists to catch, and this is the first time it has said so on a non-Cisco
    platform.
    """
    observations = analyse_device(brace_csm).observations
    shadowed = [o for o in observations if o.kind is AclObservationKind.SHADOWED]

    assert [o.entry_seq for o in shadowed] == [5, 6]
    for observation in shadowed:
        assert 4 in observation.caused_by, "the catch-all permit is the cause"


def test_the_catch_all_is_also_reported_overly_permissive(brace_csm) -> None:
    observations = analyse_device(brace_csm).observations
    permissive = [o for o in observations if o.kind is AclObservationKind.OVERLY_PERMISSIVE]

    assert [o.entry_seq for o in permissive] == [4]


def test_the_brace_terms_leave_the_training_queue(junos) -> None:
    """A line the reader understood must not be put in front of an administrator."""
    parsed = parse_configuration(
        BRACE.read_text(encoding="utf-8"), junos, file_id=BRACE.name, file_path=str(BRACE)
    )
    remaining = {node.line_number for node in parsed.residue}

    # The filter block spans lines 125-162 in the corpus file.
    assert not remaining & set(range(127, 160)), (
        "filter terms the reader consumed are still queued for review"
    )


def test_identity_is_read_from_the_brace_surface(junos) -> None:
    """A pack may declare one field twice, once per surface.

    `identity_for` returned only the first declaration, so the second was read
    by nothing — the shape DEF-12 is named for. `extract_identity` consults
    every declaration for a field now, first match winning.
    """
    identity = extract_identity(
        junos,
        BRACE.read_text(encoding="utf-8").splitlines(),
        file_id=BRACE.name,
        file_path=str(BRACE),
    )

    assert identity.hostname is not None and identity.hostname.value == "core-rtr-01"
    assert identity.os_version is not None and identity.os_version.value == "21.4R3.15"
    assert identity.hostname.evidence[0].raw_line.strip() == "host-name core-rtr-01;"


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


def test_a_bracketed_port_list_expands_in_the_set_form_too() -> None:
    """Replaces `test_a_bracketed_port_list_drops_the_filter_and_says_why`.

    That test asserted the filter was dropped, which was the behaviour until
    P18 and too strong: a bracketed list is a disjunction over one field, not an
    unreadable token. It was deleted by the change that earned it (D115).

    Asserted on the `set` surface specifically, because the expansion was
    written for the brace one. The two are the same filter language, and a
    construct that expands in one and drops the filter in the other would make
    the result depend on how the device happened to be exported.
    """
    t = junos_tree(
        _filter_line("a", "from destination-port [ ssh https ]") + _filter_line("a", "then accept")
    )
    acls, failures = extract_acls(t, junos_pack())

    assert failures == ()
    ports = [(e.dst_port.low, e.dst_port.high) for e in acls[0].entries]
    assert ports == [(22, 22), (443, 443)]
    assert {e.action for e in acls[0].entries} == {AclAction.PERMIT}


def test_several_protocols_in_one_term_are_still_refused() -> None:
    """Expansion is for ports, and the reason says so rather than generalising.

    Two protocols would need the same treatment and no configuration in this
    corpus writes one, so it is refused rather than guessed at — the same
    standing every unexercised branch has here.
    """
    t = junos_tree(
        _filter_line("a", "from protocol [ tcp udp ]") + _filter_line("a", "then accept")
    )
    _, failures = extract_acls(t, junos_pack())

    assert "several protocols" in failures[0].reason


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
