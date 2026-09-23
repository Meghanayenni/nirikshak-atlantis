"""Pattern matching, scoping, casts and field construction."""

from __future__ import annotations

import pytest

from api.models import (
    CaptureSpec,
    CastType,
    ConfidenceMethod,
    FieldState,
    MatchSpec,
    MatchType,
    PatternDef,
    PatternScope,
    UnknownReason,
    VendorPack,
)
from api.parse.block_parser import build_tree
from api.parse.casts import cast_value, is_multi_valued
from api.parse.errors import CastError
from api.parse.fields import build_field, build_fields
from api.parse.pack_engine import UnsupportedPrimitiveError, apply_pack, apply_pattern

FILE_ID = "f" * 64


def tree(text: str, **kw):
    return build_tree(text, file_id=FILE_ID, file_path="d.cfg", **kw)


def pattern(**kw) -> PatternDef:
    base = {
        "id": "p-1",
        "field": "ssh_version",
        "match": MatchSpec(type=MatchType.REGEX, pattern=r"^ip ssh version (\d+)$"),
        "capture": CaptureSpec(value="$1", cast=CastType.INT),
    }
    base.update(kw)
    return PatternDef(**base)


def pack(*patterns: PatternDef) -> VendorPack:
    return VendorPack(vendor="test", os_family="os", pack_version="1.0.0", patterns=tuple(patterns))


# ---------------------------------------------------------------------------
# Casts
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "cast", "expected"),
    [
        ("2", CastType.INT, 2),
        ("true", CastType.BOOL, True),
        ("false", CastType.BOOL, False),
        ("enabled", CastType.BOOL, True),
        ("  spaced  ", CastType.STR, "spaced"),
        ("192.0.2.0/24", CastType.CIDR, "192.0.2.0/24"),
        ("600", CastType.DURATION, 600),
        ("10 0", CastType.DURATION, 600),
        ("30 0", CastType.DURATION, 1800),
        ("0 45", CastType.DURATION, 45),
    ],
)
def test_casts(raw: str, cast: CastType, expected: object) -> None:
    assert cast_value(raw, cast) == expected


@pytest.mark.parametrize(
    ("raw", "cast"),
    [
        ("two", CastType.INT),
        ("maybe", CastType.BOOL),
        ("not-an-address", CastType.CIDR),
        ("ten zero", CastType.DURATION),
        ("1 2 3", CastType.DURATION),
        ("-5", CastType.DURATION),
    ],
)
def test_malformed_values_raise_rather_than_coercing(raw: str, cast: CastType) -> None:
    """A plausible substitute would be worse than an admitted gap."""
    with pytest.raises(CastError):
        cast_value(raw, cast)


def test_only_list_is_multi_valued() -> None:
    assert is_multi_valued(CastType.LIST)
    assert not is_multi_valued(CastType.INT)


# ---------------------------------------------------------------------------
# Matching and scope (D9)
# ---------------------------------------------------------------------------


def test_pattern_matches_trimmed_text_not_raw_line() -> None:
    """Indentation is structure; patterns should not have to re-encode it."""
    t = tree("line vty 0 4\n ip ssh version 2\n")
    p = pattern(scope=PatternScope(block=(r"^line vty \d+ \d+$",)))
    matches = apply_pattern(p, t)

    assert len(matches) == 1
    assert matches[0].value == 2
    assert matches[0].evidence.raw_line == " ip ssh version 2", "evidence keeps the indent"


def test_root_scope_excludes_nested_nodes() -> None:
    """block=None means root level only."""
    t = tree("interface Gi0/1\n ip ssh version 2\n")
    assert apply_pattern(pattern(), t) == []


def test_any_depth_scope() -> None:
    t = tree("interface Gi0/1\n ip ssh version 2\n")
    p = pattern(scope=PatternScope(block=()))
    assert len(apply_pattern(p, t)) == 1


def test_anchored_scope_distinguishes_vty_forms() -> None:
    """D9 — `line vty 0 4` and `line vty 0 15` are different scopes."""
    source = "line vty 0 4\n exec-timeout 10 0\nline vty 0 15\n exec-timeout 30 0\n"
    t = tree(source)
    timeout = PatternDef(
        id="p-t",
        field="idle_timeout_seconds",
        match=MatchSpec(type=MatchType.REGEX, pattern=r"^exec-timeout (\d+) (\d+)$"),
        capture=CaptureSpec(value="$1 $2", cast=CastType.DURATION),
        scope=PatternScope(block=(r"^line vty 0 4$",)),
    )
    exact = apply_pattern(timeout, t)
    assert [m.value for m in exact] == [600], "an exact scope must not reach the other vty block"

    both = timeout.model_copy(update={"scope": PatternScope(block=(r"^line vty \d+ \d+$",))})
    assert [m.value for m in apply_pattern(both, t)] == [600, 1800]


def test_scope_excludes_the_console_line() -> None:
    """The case the whole scoping mechanism exists for."""
    source = "line con 0\n exec-timeout 0 0\nline vty 0 4\n exec-timeout 10 0\n"
    t = tree(source)
    timeout = PatternDef(
        id="p-t",
        field="idle_timeout_seconds",
        match=MatchSpec(type=MatchType.REGEX, pattern=r"^exec-timeout (\d+) (\d+)$"),
        capture=CaptureSpec(value="$1 $2", cast=CastType.DURATION),
        scope=PatternScope(block=(r"^line vty \d+ \d+$",)),
    )
    matches = apply_pattern(timeout, t)
    assert [m.value for m in matches] == [600]
    assert matches[0].evidence.line_start == 4


def test_literal_capture_for_a_negation_form() -> None:
    t = tree("no ip http server\n")
    p = PatternDef(
        id="p-http",
        field="http_server_enabled",
        match=MatchSpec(type=MatchType.REGEX, pattern=r"^no ip http server$"),
        capture=CaptureSpec(value="false", cast=CastType.BOOL),
    )
    assert apply_pattern(p, t)[0].value is False


def test_malformed_value_yields_no_match() -> None:
    t = tree("ip ssh version 2\n")
    p = pattern(capture=CaptureSpec(value="$1", cast=CastType.CIDR))
    assert apply_pattern(p, t) == []


@pytest.mark.parametrize("primitive", [MatchType.TEXTFSM, MatchType.XPATH, MatchType.JSONPATH])
def test_deferred_primitives_raise(primitive: MatchType) -> None:
    t = tree("anything\n")
    spec = (
        MatchSpec(type=primitive, pattern="x", template="t")
        if primitive is MatchType.TEXTFSM
        else MatchSpec(type=primitive, pattern="x")
    )
    with pytest.raises(UnsupportedPrimitiveError, match="not implemented"):
        apply_pattern(pattern(match=spec), t)


# ---------------------------------------------------------------------------
# Field construction and abstention
# ---------------------------------------------------------------------------


def test_single_match_is_present_with_evidence() -> None:
    t = tree("ip ssh version 2\n")
    p = pack(pattern())
    by_field, _ = apply_pack(p, t)
    field = build_field("ssh_version", by_field["ssh_version"], p)

    assert field.state is FieldState.PRESENT
    assert field.value == 2
    assert len(field.evidence) == 1
    assert field.confidence == 1.0
    assert field.confidence_method is ConfidenceMethod.DETERMINISTIC


def test_no_match_abstains() -> None:
    p = pack(pattern())
    field = build_field("ssh_version", [], p)

    assert field.state is FieldState.UNKNOWN
    assert field.unknown_reason is UnknownReason.NO_MATCH
    assert field.value is None


def test_repeated_identical_values_keep_every_citation() -> None:
    t = tree("ip ssh version 2\nip ssh version 2\n")
    p = pack(pattern())
    by_field, _ = apply_pack(p, t)
    field = build_field("ssh_version", by_field["ssh_version"], p)

    assert field.state is FieldState.PRESENT
    assert field.value == 2
    assert [e.line_start for e in field.evidence] == [1, 2]


def test_conflicting_values_abstain_and_cite_both() -> None:
    """A disagreement is not a tie to break by position."""
    t = tree("ip ssh version 1\nip ssh version 2\n")
    p = pack(pattern())
    by_field, _ = apply_pack(p, t)
    field = build_field("ssh_version", by_field["ssh_version"], p)

    assert field.state is FieldState.UNKNOWN
    assert field.unknown_reason is UnknownReason.CONFLICTING_EVIDENCE
    assert field.value is None
    assert [e.line_start for e in field.evidence] == [1, 2], "both lines must be cited"


def test_multi_valued_field_accumulates() -> None:
    t = tree("ntp server 192.0.2.20\nntp server 192.0.2.21\n")
    p = pack(
        PatternDef(
            id="p-ntp",
            field="ntp_servers",
            match=MatchSpec(type=MatchType.REGEX, pattern=r"^ntp server (\S+)$"),
            capture=CaptureSpec(value="$1", cast=CastType.LIST),
        )
    )
    by_field, _ = apply_pack(p, t)
    field = build_field("ntp_servers", by_field["ntp_servers"], p)

    assert field.state is FieldState.PRESENT
    assert field.value == ["192.0.2.20", "192.0.2.21"]
    assert len(field.evidence) == 2


def test_declared_but_unmatched_fields_are_still_reported() -> None:
    """Key presence distinguishes 'absent from the config' from 'cannot parse'."""
    p = pack(pattern())
    fields = build_fields({}, p)

    assert "ssh_version" in fields
    assert fields["ssh_version"].state is FieldState.UNKNOWN


def test_fields_the_pack_never_declares_are_omitted() -> None:
    fields = build_fields({}, pack(pattern()))
    assert "aaa_enabled" not in fields


def test_every_present_field_has_evidence() -> None:
    t = tree("ip ssh version 2\n")
    p = pack(pattern())
    by_field, _ = apply_pack(p, t)

    for name, field in build_fields(by_field, p).items():
        if field.state is FieldState.PRESENT:
            assert field.evidence, f"{name} is PRESENT without evidence"


def test_residue_is_what_no_pattern_touched() -> None:
    from api.parse.service import collect_residue

    t = tree("ip ssh version 2\nsomething unrecognised\n")
    p = pack(pattern())
    _, matched = apply_pack(p, t)
    residue = collect_residue(t, matched)

    assert [n.text for n in residue] == ["something unrecognised"]


def test_residue_excludes_comments_and_literal_bodies() -> None:
    from api.models import LiteralBlock
    from api.parse.service import collect_residue

    banner = LiteralBlock(name="banner", open=r"^banner \S+ (\S+)$", terminator_group=1)
    t = tree(
        "! a comment\nbanner motd ^C\nprose\n^C\nunrecognised\n",
        comment_prefixes=("!",),
        literal_blocks=(banner,),
    )
    p = pack(pattern())
    _, matched = apply_pack(p, t)
    residue_text = [n.text for n in collect_residue(t, matched)]

    assert "! a comment" not in residue_text
    assert "prose" not in residue_text
    assert "unrecognised" in residue_text


# ---------------------------------------------------------------------------
# DEF-17 — per-field merge semantics (P16)
# ---------------------------------------------------------------------------


def _telnet_pattern(pid: str, regex: str, literal: str) -> PatternDef:
    """A presence pattern asserting a literal boolean, as the compiler builds."""
    return PatternDef(
        id=pid,
        field="telnet_enabled",
        match=MatchSpec(type=MatchType.REGEX, pattern=regex),
        capture=CaptureSpec(value=literal, cast=CastType.BOOL),
    )


def test_a_reachability_boolean_takes_the_worst_case_and_cites_both_lines() -> None:
    """DEF-17 — `line vty 0 4` ssh-only and `line vty 5 15` telnet is not a tie.

    Both statements are true. Together they say telnet is reachable, because a
    device is reachable by any path that reaches it. Abstaining discarded that.
    """
    p = pack(
        _telnet_pattern("p-telnet-off", r"^transport input ssh$", "false"),
        _telnet_pattern("p-telnet-on", r"^transport input telnet ssh$", "true"),
    )
    t = tree("transport input ssh\ntransport input telnet ssh\n")
    by_field, _ = apply_pack(p, t)
    field = build_field("telnet_enabled", by_field["telnet_enabled"], p)

    assert field.state is FieldState.PRESENT
    assert field.value is True

    # Every contributing line, including the one that said the safer thing: an
    # operator closing the gap needs to know which range to change.
    assert len(field.evidence) == 2
    cited = {e.raw_line.strip() for e in field.evidence}
    assert cited == {"transport input ssh", "transport input telnet ssh"}


def test_the_worst_case_holds_whichever_line_comes_first() -> None:
    """Order must not decide a security fact."""
    p = pack(
        _telnet_pattern("p-telnet-on", r"^transport input telnet ssh$", "true"),
        _telnet_pattern("p-telnet-off", r"^transport input ssh$", "false"),
    )
    t = tree("transport input telnet ssh\ntransport input ssh\n")
    by_field, _ = apply_pack(p, t)

    assert build_field("telnet_enabled", by_field["telnet_enabled"], p).value is True


def test_a_field_with_no_declared_policy_still_abstains() -> None:
    """The default, and the reason the table is an opt-in.

    Two vty ranges with different idle timeouts are a real "which one did you
    mean" question. Nothing in the configuration answers it, so neither does the
    canonical model.
    """
    p = pack(
        pattern(
            id="p-idle",
            field="idle_timeout_seconds",
            match=MatchSpec(type=MatchType.REGEX, pattern=r"^exec-timeout (\d+) 0$"),
            capture=CaptureSpec(value="$1", cast=CastType.INT),
        )
    )
    t = tree("exec-timeout 0 0\nexec-timeout 30 0\n")
    by_field, _ = apply_pack(p, t)
    field = build_field("idle_timeout_seconds", by_field["idle_timeout_seconds"], p)

    assert field.state is FieldState.UNKNOWN
    assert field.unknown_reason is UnknownReason.CONFLICTING_EVIDENCE
    assert len(field.evidence) == 2


def test_the_mirror_policy_resolves_to_false(monkeypatch: pytest.MonkeyPatch) -> None:
    """`WORST_CASE_FALSE` is the shape snmp_v3_only will need.

    Exercised on a constructed field rather than by opting a real one in: a v1/v2c
    community is dispositive evidence that SNMP is not v3-only, but no pack
    declares an SNMP pattern yet, so opting the real field in would be a claim
    nothing could exercise.
    """
    from api.models.enums import MergePolicy
    from api.parse import fields as fields_module

    monkeypatch.setitem(
        fields_module.FIELD_MERGE_POLICY, "snmp_v3_only", MergePolicy.WORST_CASE_FALSE
    )

    p = pack(
        PatternDef(
            id="p-v3",
            field="snmp_v3_only",
            match=MatchSpec(type=MatchType.REGEX, pattern=r"^snmp-server user .*$"),
            capture=CaptureSpec(value="true", cast=CastType.BOOL),
        ),
        PatternDef(
            id="p-v2c",
            field="snmp_v3_only",
            match=MatchSpec(type=MatchType.REGEX, pattern=r"^snmp-server community .*$"),
            capture=CaptureSpec(value="false", cast=CastType.BOOL),
        ),
    )
    t = tree("snmp-server user netmon GRP v3 auth sha K\nsnmp-server community public RO\n")
    by_field, _ = apply_pack(p, t)
    field = build_field("snmp_v3_only", by_field["snmp_v3_only"], p)

    assert field.value is False
    assert field.state is FieldState.PRESENT
    assert len(field.evidence) == 2
