"""Token-shape signatures, for clustering unknown lines.

`UnknownLine.normalised_line` has been an empty string since P5, where
`api/normalise/residue.py` left it with the note *"token-shape signature is
P10's clustering concern"*. This is that concern.

A signature replaces the parts of a line that vary between devices with typed
placeholders and keeps everything else exactly as written:

    ntp server 192.0.2.20        ->  ntp server <IP>
    ntp server 192.0.2.21        ->  ntp server <IP>
    exec-timeout 10 0            ->  exec-timeout <N> <N>
    interface GigabitEthernet0/0 ->  interface <WORD>

Two lines with the same signature are the same *command* on different values,
which is what makes clustering meaningful: an administrator confirming
`ntp server <IP>` confirms it for every device in the fleet at once.

**The signatures are deliberately boring.** DEVELOPER_GUIDE.md §4 requires generated
patterns be predictable enough that an administrator can read and verify them,
and the signature is what they will be shown next to the line. A clever
normaliser that collapsed more would produce clusters nobody could check.

This module is pure string handling. It imports nothing from `api/` and no
machine-learning library, so clustering works with the `[ai]` extra uninstalled.
"""

from __future__ import annotations

import re

IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$")
IPV6ISH = re.compile(r"^[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,}(?:/\d{1,3})?$")
NUMBER = re.compile(r"^\d+$")
DECIMAL = re.compile(r"^\d+\.\d+$")
VERSION_LITERAL = re.compile(r"^[vV]\d+(?:\.\d+)*$")
"""A bare version token such as `v2`.

Tested before the interface rule, which it would otherwise satisfy: `v2` is a
letter followed by a digit, and so is `ge0`. Getting this wrong is not a
clustering error — both shapes group the same lines either way — but the
signature is shown to an administrator beside the line it describes, and
`protocol-version <IF>` reads as a mistake in the tool.
"""
INTERFACE = re.compile(r"^[A-Za-z][A-Za-z-]*\d[\d/.:]*$")
QUOTED = re.compile(r'^".*"$|^\'.*\'$')

IP = "<IP>"
NUM = "<N>"
VERSION = "<VER>"
IFACE = "<IF>"
WORD = "<WORD>"
STRING = "<STR>"

MAX_TOKENS = 24
"""Signatures stop here.

A configuration line long enough to exceed this is a description or a free-text
field, not a command shape worth clustering, and a signature that ran on would
be unreadable in the training interface.
"""


def token_shape(token: str) -> str | None:
    """The placeholder for one token, or `None` to keep the token as written.

    Order matters: an IPv4 address is also a dotted decimal, and an interface
    name contains digits. The most specific test wins, and each is anchored so a
    partial match cannot reclassify a token.
    """
    if IPV4.match(token) or IPV6ISH.match(token):
        return IP
    if DECIMAL.match(token) or VERSION_LITERAL.match(token):
        return VERSION
    if NUMBER.match(token):
        return NUM
    if QUOTED.match(token):
        return STRING
    if INTERFACE.match(token):
        return IFACE
    return None


def signature(line: str, *, max_tokens: int = MAX_TOKENS) -> str:
    """The token-shape signature of one configuration line.

    Whitespace is collapsed and leading indentation dropped: indentation is
    structure, already carried by `block_path`, and two lines that differ only
    by depth are the same command shape.
    """
    tokens = line.strip().split()
    if not tokens:
        return ""

    shaped: list[str] = []
    for token in tokens[:max_tokens]:
        shaped.append(token_shape(token) or token)

    if len(tokens) > max_tokens:
        shaped.append("...")
    return " ".join(shaped)


def is_generic(sig: str) -> bool:
    """Whether a signature carries no command vocabulary at all.

    A signature of nothing but placeholders — `<IP>`, `<N> <N>` — describes a
    fragment rather than a command, and clustering on it would group lines that
    have nothing to do with each other. Such lines are kept in the queue but are
    never used to seed or match a cluster.
    """
    tokens = sig.split()
    if not tokens:
        return True
    return all(t.startswith("<") and t.endswith(">") or t == "..." for t in tokens)
