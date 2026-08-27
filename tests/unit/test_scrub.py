"""Secret scrubbing at the inference boundary, and nowhere else (decision D12).

The property that matters most here is not what the scrubber removes — it is
what it must never touch. Evidence fidelity is the foundation of every claim
NIRIKSHAK makes, so the stored configuration and every `Evidence` object stay
byte-identical to what the operator wrote. The scrubbed text is a *derived view*
for the P10 embedding index.

These tests are synthetic by necessity. `corpus/MANIFEST.yaml` requires no
credentials in any form, including hashed ones, so there is deliberately nothing
in the corpus to catch. That is a known limit, recorded in ADR 0012: P10 must
re-scrub at its own boundary rather than trusting this pass.
"""

from __future__ import annotations

import pytest

from api.models.enums import SyntaxMode
from api.normalise.residue import to_unknown_lines
from api.parse.block_parser import build_tree
from api.security.scrub import REDACTED, contains_secret, scrub_for_inference, scrub_line

# ---------------------------------------------------------------------------
# Secrets are removed
# ---------------------------------------------------------------------------

SECRET_LINES = [
    "username admin password cisco123",
    "username admin secret 5 $1$abcd$efghijklmnop",
    "enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0",
    "enable password 7 04585A150C2E1D1C",
    "snmp-server community public RO",
    "snmp-server community s3cr3t RW",
    "crypto isakmp key MySharedKey address 192.0.2.5",
    "set system root-authentication encrypted-password $6$xyz$abcdef",
    "wlan security psk MyWifiPassword",
]


@pytest.mark.parametrize("line", SECRET_LINES)
def test_secret_material_does_not_survive(line: str) -> None:
    """No credential reaches the inference representation."""
    scrubbed = scrub_for_inference(line)

    assert REDACTED in scrubbed, f"nothing was redacted in {line!r}"
    assert not contains_secret(scrubbed), f"a secret survived in {scrubbed!r}"


@pytest.mark.parametrize("line", SECRET_LINES)
def test_the_directive_keyword_survives(line: str) -> None:
    """Over-redaction is cheap; erasure is not.

    The line still has to be useful for clustering at P10, so the directive keeps
    its shape and only the credential material goes.
    """
    scrubbed = scrub_for_inference(line)
    first_token = line.split()[0]

    assert first_token in scrubbed
    assert scrubbed != REDACTED, "the whole line was erased, leaving nothing to cluster"


def test_hash_literals_are_caught_without_a_keyword() -> None:
    scrubbed = scrub_for_inference("some-directive $6$salt$hashhashhash")

    assert "$6$" not in scrubbed
    assert REDACTED in scrubbed


def test_a_type_digit_is_not_mistaken_for_the_secret() -> None:
    """`password 7 04585A...` — the type tag is structure, the rest is not."""
    scrubbed = scrub_for_inference("enable password 7 04585A150C2E1D1C")

    assert "04585A150C2E1D1C" not in scrubbed
    assert "7" in scrubbed


# ---------------------------------------------------------------------------
# Non-secret configuration stays usable
# ---------------------------------------------------------------------------

BENIGN_LINES = [
    "ip ssh version 2",
    "no ip http server",
    "transport input ssh",
    "exec-timeout 10 0",
    "logging host 192.0.2.10",
    "ntp server 192.0.2.20",
    "interface GigabitEthernet0/0/0",
    "switchport access vlan 30",
    "set system services ssh protocol-version v2",
]


@pytest.mark.parametrize("line", BENIGN_LINES)
def test_benign_configuration_is_untouched(line: str) -> None:
    """Redacting a line that was never sensitive destroys signal for no gain."""
    assert scrub_line(line) == line
    assert REDACTED not in scrub_for_inference(line)


def test_scrubbing_is_pure() -> None:
    """The caller's original string is always still available for evidence."""
    original = "username admin password cisco123"
    scrub_for_inference(original)

    assert original == "username admin password cisco123"


@pytest.mark.parametrize("line", SECRET_LINES + BENIGN_LINES)
def test_scrubbing_is_idempotent(line: str) -> None:
    """A line may be scrubbed more than once on its way to inference.

    The failure this guards against is subtle: a second pass eating the Cisco
    type tag, so `password 7 <redacted>` degrades to
    `password <redacted> <redacted>` and the fact that a type 7 (trivially
    reversible) encoding was used is silently lost.
    """
    once = scrub_line(line)

    assert scrub_line(once) == once


def test_a_fully_redacted_line_is_never_empty() -> None:
    """`UnknownLine.raw_line_scrubbed` is min_length=1; an empty result would raise."""
    assert scrub_for_inference("password hunter2").strip()
    assert scrub_for_inference("$1$aa$bbbb").strip()


# ---------------------------------------------------------------------------
# The stored source and its evidence are never scrubbed
# ---------------------------------------------------------------------------

CONFIG_WITH_SECRET = (
    "hostname rtr-secret-01\n"
    "username admin password cisco123\n"
    "ip ssh version 2\n"
    "no ip http server\n"
)


def _tree():
    return build_tree(
        CONFIG_WITH_SECRET,
        file_id="f1",
        file_path="rtr.cfg",
        mode=SyntaxMode.INDENT,
    )


def test_the_parsed_source_keeps_the_secret_verbatim() -> None:
    """Redacting at rest would destroy the thing every finding depends on.

    "Your credentials are weak" beside `<redacted>` is not evidence of anything.
    Secrets are scrubbed before inference, not before storage — the other half of
    the decision `api/ingest/blobs.py` took at P3.
    """
    tree = _tree()

    assert tree.verify_lossless(CONFIG_WITH_SECRET)
    assert "cisco123" in tree.reconstruct()


def test_evidence_cites_the_unscrubbed_line() -> None:
    tree = _tree()
    node = next(n for n in tree.nodes.values() if n.text.startswith("username"))
    evidence = node.to_evidence("rtr.cfg")

    assert "cisco123" in evidence.raw_line
    assert REDACTED not in evidence.raw_line


def test_scrubbing_does_not_move_line_numbers() -> None:
    """A suggestion made about a scrubbed line must resolve to real source text."""
    tree = _tree()
    nodes = tuple(tree.in_source_order())
    lines = to_unknown_lines(nodes, file_id="f1")

    assert [line.line_number for line in lines] == [n.line_number for n in nodes]
    assert [line.block_path for line in lines] == [n.block_path for n in nodes]


def test_residue_reaches_the_queue_scrubbed() -> None:
    tree = _tree()
    nodes = tuple(tree.in_source_order())
    lines = to_unknown_lines(nodes, file_id="f1")
    secret_line = next(line for line in lines if line.line_number == 2)

    assert "cisco123" not in secret_line.raw_line_scrubbed
    assert REDACTED in secret_line.raw_line_scrubbed
    # ...while the tree it came from still has it.
    assert "cisco123" in tree.reconstruct()


# ---------------------------------------------------------------------------
# A scrubbed representation cannot become a verdict
# ---------------------------------------------------------------------------


def test_the_scrubbed_representation_is_not_a_field() -> None:
    """`UnknownLine` carries no value, state, confidence or evidence.

    The compliance engine reads `CSM.fields`. Residue is a separate tuple of a
    different type with no route into a `Field`, so scrubbed text has no path to
    a PASS or a FAIL — it is a training queue, not a claim.
    """
    from api.models.csm import UnknownLine

    forbidden = {"value", "state", "confidence", "confidence_method", "evidence"}
    assert not (forbidden & set(UnknownLine.model_fields))


def test_residue_is_not_reachable_from_the_fields_mapping() -> None:
    from api.models.csm import CanonicalSecurityModel, DeviceIdentity, UnknownLine

    csm = CanonicalSecurityModel(
        device=DeviceIdentity(device_id="d1"),
        residue=(
            UnknownLine(
                line_number=2, raw_line_scrubbed=f"username admin password {REDACTED}", file_id="f1"
            ),
        ),
    )

    assert csm.fields == {}
    assert csm.determinable_fields() == {}
    assert csm.residue_count == 1
