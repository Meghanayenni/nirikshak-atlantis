"""Deliberately awkward inputs for the ingestion tests.

These are *test fixtures*, not corpus. They are mechanical — a twelve-line file
with intentional CRLF damage exercises a splitter and would flatter any parser —
so they live here permanently and never migrate into `corpus/`. No metric is
ever computed on them (decision R9, category A).
"""

from __future__ import annotations

import io
import zipfile

# --- line-ending and counting cases (findings F1 and F3) -------------------

MIXED_ENDINGS = "line1\r\nline2\nline3\rline4\r\nline5"
"""Five lines, three different terminators. Numbering must match an editor's."""

BANNER_WITH_VERTICAL_TAB = (
    "hostname r1\nbanner motd ^C\x0bWARNING\x0c authorised only ^C\nip ssh version 2"
)
"""Three lines. `str.splitlines()` would report five — the F1 regression."""

NO_TRAILING_NEWLINE = "a\nb"
ONE_TRAILING_NEWLINE = "a\nb\n"
TWO_TRAILING_NEWLINES = "a\nb\n\n"
EMPTY = ""

UNICODE_CONFIG = "hostname राउटर-०१\n! description: em—dash, ✓ tick, ünlaut\nip ssh version 2\n"

# --- binary masquerading as configuration (finding F2) --------------------

PNG_BYTES = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + bytes(64)
ELF_BYTES = b"\x7fELF\x02\x01\x01\x00" + bytes(64)
GZIP_BYTES = b"\x1f\x8b\x08\x00" + bytes(64)

UTF16_CONFIG = "hostname sw-01\nip ssh version 2\n".encode("utf-16")
"""Legitimate text that is full of NUL bytes — must be accepted, not rejected."""

UTF8_BOM_CONFIG = "﻿hostname sw-02\nip ssh version 2\n".encode("utf-8-sig")

# --- format cases ----------------------------------------------------------

MALFORMED_XML = '<?xml version="1.0"?>\n<config><unclosed>\n'
MALFORMED_JSON = '{"SecurityGroups": [{"GroupId": "sg-1",]}\n'
VALID_JSON = '{"SecurityGroups": [{"GroupId": "sg-01", "IpPermissions": []}]}\n'

# --- vendor detection cases ------------------------------------------------

CISCO_IOS = """version 17.9
service timestamps debug datetime msec
hostname rtr-test-01
ip ssh version 2
interface GigabitEthernet0/0/0
 ip address 192.0.2.1 255.255.255.0
line vty 0 4
 transport input ssh
"""

ARISTA_EOS = """! device: sw-test-01 (DCS-7050SX3, EOS-4.29.2F)
transceiver qsfp default-mode 4x10G
hostname sw-test-01
management api http-commands
   no shutdown
interface Ethernet1
   ip address 192.0.2.65/31
"""

AMBIGUOUS_IOS_LIKE = """hostname amb-01
line vty 0 4
 transport input ssh
"""
"""Matches a low-weight signature in both the IOS and EOS packs and clears
neither threshold — the ambiguity case the two-threshold rule exists for."""

UNSUPPORTED_VENDOR = """system {
    host-name mikrotik-01;
    identity "unknown-platform";
}
/ip service set telnet disabled=no
/system clock set time-zone-name=UTC
"""

NOTHING_LIKE_A_CONFIG = """The quick brown fox jumps over the lazy dog.
Lorem ipsum dolor sit amet, consectetur adipiscing elit.
"""


def make_zip(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def zip_slip() -> bytes:
    """An archive whose entry escapes the extraction directory."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("../../etc/passwd", b"root:x:0:0\n")
    return buffer.getvalue()


def zip_bomb(ratio_target: int = 5000) -> bytes:
    """Highly compressible content — small archive, large expansion."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        archive.writestr("bomb.cfg", b"A" * (ratio_target * 1000))
    return buffer.getvalue()
