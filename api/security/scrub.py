"""Redacting secrets on the way to inference — and nowhere else (decision D12).

The pipeline this sits in has one shape, and the order matters:

    raw configuration      kept verbatim, byte for byte
        ↓
    stored source / evidence     also verbatim — this is what a report cites
        ↓
    scrubbed representation      built here, a separate object
        ↓
    inference boundary (P10)     the only consumer

**Scrubbing never touches the stored configuration or any Evidence.** Redacting
at rest would destroy the thing the whole system is built on: an operator has to
be able to read the exact line that justified a finding, and "your SNMP community
is weak" beside `<redacted>` is not evidence of anything. `api/ingest/blobs.py`
made that decision at P3 and this module is its other half — secrets are scrubbed
before *inference*, not before *storage*.

So a scrubbed line is a **derived view**, never a replacement. It keeps its line
number, so a suggestion made about it still resolves to real source text.

Two failure directions, and they are not symmetric:

  * **Under-redaction** puts a credential into an embedding index, which is
    irreversible once written. This is the one that matters.
  * **Over-redaction** costs the similarity layer some signal on a line that was
    never sensitive. Recoverable, and cheap by comparison.

So the patterns here lean toward redacting, and the token that replaces a secret
preserves the *shape* of the line — the directive keeps its keyword, only the
value goes. A line reduced to nothing would be useless for clustering and would
also violate `UnknownLine.raw_line_scrubbed`'s non-empty requirement.

**This module cannot validate itself against the corpus.** Every corpus file is
sanitised by policy — `corpus/MANIFEST.yaml` requires no credentials in any form,
including hashed ones — so there is deliberately nothing here to catch. The tests
are therefore synthetic, and that is a known limit rather than an oversight: P10
must re-scrub at its own boundary rather than trusting this pass. Defence in
depth, not a single gate.
"""

from __future__ import annotations

import re

REDACTED = "<redacted>"
"""What replaces a secret. Non-empty by design.

An empty replacement would leave a line that cannot be stored as an
`UnknownLine`, and would also erase the fact that something was removed. A
visible marker says "a secret was here" without saying what it was.
"""

_KEYWORD = r"(?:password|passwd|secret|key|community|psk|pre-shared-key|passphrase)"

_NOT_REDACTED = rf"(?!{re.escape(REDACTED)})"
"""Guards every value position, so the marker can never itself be treated as a
secret. This is what makes scrubbing idempotent — see `scrub_line`."""

SECRET_PATTERN = re.compile(
    # `password cisco123` - `enable secret 5 $1$...` - `community public RO`
    #
    # The optional `(\s+\d+)` is the Cisco type tag. It is kept, because which
    # encoding a device used is itself security-relevant: a type 7 password is
    # trivially reversible, and a report should be able to say so without ever
    # holding the material.
    #
    # `\S+` stops at the first token, so a trailing `RO` / `RW` permission or an
    # `address 192.0.2.5` clause survives and the line stays clusterable.
    #
    # The trailing guard is what stops a second pass eating the type tag: in
    # `password 7 <redacted>` the regex must not fall back to treating `7` as the
    # secret, so a value followed by the marker does not match at all.
    rf"\b(?P<kw>{_KEYWORD})(?P<tag>\s+\d+)?\s+{_NOT_REDACTED}\S+"
    rf"(?!\s*{re.escape(REDACTED)})"
    # A bare crypt hash anywhere on the line, with or without a keyword.
    rf"|(?P<hash>\$\d[a-z0-9]*\${_NOT_REDACTED}\S+)",
    re.IGNORECASE,
)
"""One pattern, one pass, alternatives tried left to right.

Deliberately not a list of patterns applied in sequence. Sequential passes
re-fire on their own output: `password 7 04585A` becomes `password 7 <redacted>`
and then `password <redacted> <redacted>`, silently destroying the type tag. A
single pass cannot do that."""


def scrub_line(raw: str) -> str:
    """Return `raw` with credential material replaced by `REDACTED`.

    Pure: the input string is never modified in place, and the caller's original
    remains available for evidence. Leading whitespace is preserved so a scrubbed
    line still reflects the structure it came from.

    Idempotent — `scrub_line(scrub_line(x)) == scrub_line(x)` — because every
    value position refuses to match the marker. That matters at a boundary where
    a line may be scrubbed more than once on its way to inference.
    """
    return SECRET_PATTERN.sub(_replace, raw)


def _replace(match: re.Match[str]) -> str:
    """Keep the directive keyword and any type tag; replace the rest.

    Those are structure. Everything else the pattern matched was the secret.
    """
    if match.group("hash") is not None:
        return REDACTED
    kept = match.group("kw") + (match.group("tag") or "")
    return f"{kept} {REDACTED}"


def contains_secret(raw: str) -> bool:
    """Whether this text still holds material a redaction rule would remove.

    Defined as "scrubbing would change it", so it stays consistent with
    `scrub_line` by construction and reports False for text already scrubbed.
    Used to assert at the inference boundary that nothing unscrubbed is about to
    be sent — never to decide *whether* to scrub. Everything is scrubbed.
    """
    return scrub_line(raw) != raw


def scrub_for_inference(raw: str) -> str:
    """The inference-boundary entry point.

    Guarantees a non-empty result, because a fully-redacted line still has to be
    storable and still carries the information that *something* was there.
    """
    scrubbed = scrub_line(raw).strip()
    return scrubbed if scrubbed else REDACTED
