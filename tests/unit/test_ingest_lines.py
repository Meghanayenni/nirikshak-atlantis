"""Line splitting, counting and hashing — findings F1 and F3.

Every citation NIRIKSHAK produces names a line number. If ours disagree with the
number an operator sees when they open the file, every piece of evidence in the
system is quietly wrong. These are the tests that keep that from happening.
"""

from __future__ import annotations

import pytest

from api.ingest.lines import (
    count_lines,
    hash_line,
    line_records,
    normalise_terminators,
    reconstruct,
    split_lines,
)
from tests.fixtures import configs

# ---------------------------------------------------------------------------
# F1 — never str.splitlines()
# ---------------------------------------------------------------------------


def test_vertical_tab_does_not_split_a_banner() -> None:
    """The F1 regression, stated directly."""
    text = configs.BANNER_WITH_VERTICAL_TAB

    assert len(text.splitlines()) == 5, "fixture no longer exercises the divergence"
    assert count_lines(text) == 3

    result = split_lines(text)
    assert result[1] == "banner motd ^C\x0bWARNING\x0c authorised only ^C"


@pytest.mark.parametrize(
    "char",
    ["\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", " ", " "],
)
def test_unicode_break_characters_do_not_split(char: str) -> None:
    """Eight characters Python treats as breaks and an editor does not."""
    text = f"hostname r1\ndescription a{char}b\nip ssh version 2"

    assert len(text.splitlines()) > 3, f"{char!r} is expected to fool splitlines()"
    assert count_lines(text) == 3
    assert split_lines(text)[1] == f"description a{char}b"


def test_mixed_line_endings_number_correctly() -> None:
    result = split_lines(configs.MIXED_ENDINGS)
    assert result == ["line1", "line2", "line3", "line4", "line5"]


def test_line_numbers_are_one_based_and_contiguous() -> None:
    records = line_records(configs.MIXED_ENDINGS)
    assert [r.line_number for r in records] == [1, 2, 3, 4, 5]
    assert [r.text for r in records] == ["line1", "line2", "line3", "line4", "line5"]


# ---------------------------------------------------------------------------
# F3 — the trailing-newline trap
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (configs.EMPTY, 0),
        (configs.NO_TRAILING_NEWLINE, 2),
        (configs.ONE_TRAILING_NEWLINE, 2),
        (configs.TWO_TRAILING_NEWLINES, 3),
        ("\n", 1),
        ("a", 1),
    ],
)
def test_trailing_newline_counting(text: str, expected: int) -> None:
    """One terminator ends a line; two mean there is genuinely a blank one."""
    assert count_lines(text) == expected


def test_empty_file_has_no_lines() -> None:
    assert split_lines("") == []
    assert line_records("") == []


def test_one_trailing_newline_leaves_no_phantom_line() -> None:
    assert split_lines("a\nb\n") == ["a", "b"]


def test_two_trailing_newlines_keep_the_blank_line() -> None:
    assert split_lines("a\nb\n\n") == ["a", "b", ""]


# ---------------------------------------------------------------------------
# Hashing and reconstruction
# ---------------------------------------------------------------------------


def test_identical_lines_hash_identically() -> None:
    """The whole basis of the fleet-wide cache."""
    assert hash_line("ip ssh version 2") == hash_line("ip ssh version 2")
    assert hash_line("ip ssh version 2") != hash_line("ip ssh version 1")


def test_hash_is_stable_across_calls() -> None:
    text = configs.CISCO_IOS
    assert [r.line_sha256 for r in line_records(text)] == [
        r.line_sha256 for r in line_records(text)
    ]


def test_whitespace_is_significant_to_the_hash() -> None:
    """Indentation carries meaning in a configuration; it must not be folded."""
    assert hash_line(" exec-timeout 10 0") != hash_line("exec-timeout 10 0")


def test_reconstruction_is_lossless_modulo_terminators() -> None:
    text = configs.CISCO_IOS
    assert reconstruct(split_lines(text)) == normalise_terminators(text).rstrip("\n")


@pytest.mark.parametrize(
    "text",
    [
        configs.CISCO_IOS,
        configs.ARISTA_EOS,
        configs.UNICODE_CONFIG,
        configs.MIXED_ENDINGS,
        configs.BANNER_WITH_VERTICAL_TAB,
    ],
)
def test_property_split_then_reconstruct(text: str) -> None:
    normalised = normalise_terminators(text)
    if normalised.endswith("\n"):
        normalised = normalised[:-1]
    assert reconstruct(split_lines(text)) == normalised


def test_unicode_lines_hash_and_survive() -> None:
    records = line_records(configs.UNICODE_CONFIG)
    assert records[0].text == "hostname राउटर-०१"
    assert len(records[0].line_sha256) == 64
