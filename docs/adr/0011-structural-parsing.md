# ADR 0011 — Structural parsing and the first Cisco parsing pack

- **Status:** Accepted
- **Date:** 2026-08-27
- **Phase:** P4
- **Decisions:** D6 (confidence populations), D7 (literal blocks), D8 (deferred
  modes), D9 (anchored scopes)

## Context

P4 implements the R4 structural parser and turns the detection-only Cisco pack
into a real parsing pack. The P1 `ConfigTree` contract and its conformance suite
are the specification; no defect was found in either, so neither changed.

## The conformance suite came first

`tests/unit/test_config_tree.py` was written at P1, before any parser existed,
using a test-local `build_indent_tree` helper. At P4 that helper's body was
replaced with a call to `api.parse.block_parser.build_tree` and **nothing else
changed** — 17 example-based tests and three property tests generating 150 cases
between them, 167 in all, now run against the real implementation.

That ordering is the point. The assertions cannot have been shaped to fit the
parser, because the parser did not exist when they were written. When a
conformance suite is authored afterwards it tends to describe what the code
does rather than what it should do.

**The suite passed against the real parser with zero assertion changes.** The
whole P4 diff to `tests/unit/test_config_tree.py` is the module docstring, the
import, and the helper body; every `assert` in the file is byte-identical to
what P1 committed. That is the claim this section is making, and it is checkable
with `git diff`.

The one structural question the P1 suite does *not* settle is inconsistent
indent widths — what a line at indent 3 is a child of when the line above it
sits at indent 6 and the one above that at indent 2. The parser treats it as a
child of the indent-2 line, because it is still deeper than that line even
though it is shallower than the one immediately before it, and that is what an
operator reading the file would conclude. The P1 suite had no case for it, so
the rule is pinned by a new test —
`test_inconsistent_indent_widths` in `tests/unit/test_block_parser.py` — with
the reasoning written into the test rather than left to the reader.

## Three kinds of line are not nodes

### Comments — a safety property

A commented-out directive must never produce a PRESENT field. If `! ip ssh
version 1` became a node, a pattern would match it and NIRIKSHAK would report a
security fact that is not in effect — with a citation, which makes it more
convincing rather than less.

Comment prefixes are pack data (`comment_prefixes`), not a parser assumption. A
test asserts that a commented-out directive produces no field at all.

Identity extraction is deliberately unaffected: P3's `extract_identity` runs over
the raw line list rather than the tree, which is why `! model ISR4331` still
yields a model. Metadata legitimately lives in comments; active security
configuration never does. The asymmetry is intentional.

### Blank lines

No command, and they would otherwise flood the residue queue.

### Literal blocks (D7) — generalised, not banner-specific

`banner motd ^C … ^C`, certificate blocks closing on `quit`, key blocks. The
body is content, not commands.

Two things go wrong if such a body is treated as configuration. It fills the
training queue with prose, and — much worse — it becomes reachable by pattern
matching, so a banner reading *"ip ssh version 1 is prohibited"* would produce a
fact that is not true of the device.

`LiteralBlock` supports both terminator styles:

| Style | Example | Declaration |
| --- | --- | --- |
| Captured delimiter | `banner motd ^C` … `^C` | `open: '^banner \S+ (\S+)$'`, `terminator_group: 1` |
| Fixed literal | `crypto pki certificate chain …` … `quit` | `terminator: 'quit'` |

The opener stays a node so `banner_present` can cite it; everything to the
terminator becomes `UnplacedLine(reason="literal block body")` — preserved,
line-numbered, reconstructed, and beyond the engine's reach. An unterminated
block raises rather than swallowing the rest of the file.

**Only `banner` is declared in the Cisco pack**, because only a banner appears in
the development corpus. The mechanism handles certificates and key blocks and is
tested doing so, but declaring them in the pack would mean authoring from general
Cisco knowledge rather than from evidence. When a corpus file contains one, the
declaration follows. Until then such a body becomes residue — visible and
inspectable, which is the safe failure.

## Deferred syntax modes raise (D8)

`indent` and `set_path` are implemented; the corpus has files for both. `brace`
and `json` have no corpus example at all. `xml` has only the PAN-OS holdout, so
building it now would mean either testing against files we have committed not to
open, or building blind.

A deferred mode raises `UnsupportedSyntaxModeError`. It does **not** return an
empty `ConfigTree`, which would be indistinguishable from a cleanly parsed empty
configuration: every field would read UNKNOWN, the file would look handled, and
nothing would say the parser had declined. The same applies to deferred match
primitives.

**Corpus prerequisite recorded**: see `docs/CORPUS_PREREQUISITES.md`. XML parsing
cannot be implemented until a legitimately sourced XML sample independent of the
holdout exists. A self-authored fixture is explicitly not sufficient — building a
parser against a shape we invented would let us claim XML support without ever
having met the real thing.

## Anchored scopes (D9)

`PatternScope.block` entries are anchored regular expressions matched with
`re.fullmatch` against each `block_path` element. Unanchored substring matching
cannot distinguish `line vty 0 4` from `line vty 0 15`, and a scope that quietly
matches more blocks than its author intended is how a console timeout ends up
reported as a management idle timeout.

Three scope forms:

| `block` | Meaning |
| --- | --- |
| `null` | Root level only |
| `()` | Any depth |
| `('^line vty \d+ \d+$',)` | Inside a matching block |

Numeric generalisation is written out deliberately, never assumed. When P11
compiles an admin-confirmed pattern it will default to the literal-escaped
confirmed header; generalising a range will be an explicit opt-in.

**Not done in P4, recorded as a future refinement:** `block_path` remains a tuple
of header strings rather than structured components. Decomposing `line vty 0 4`
into a type and a range would make scoping more expressive, and it is a larger
change than P4 should carry.

## Confidence populations (D6)

| Population | Floor | Notes |
| --- | --- | --- |
| `deterministic` | **exactly 1.0** | A pattern matched or it did not |
| `admin_confirmed` | **exactly 1.0** | A human confirmed or did not |
| `platform_default` | its own floor (0.90) | Sourced or not used |
| `calibrated_similarity` | the calibrated threshold | The one calibrated number |
| `uncalibrated_similarity` | always UNKNOWN | A raw score is not a confidence |

Before P4, one threshold applied to all four populations. That contradicted R7's
own reasoning: a threshold calibrated against similarity scores has no meaning
applied to a parser confidence, because the numbers are not comparable.

Deterministic confidence is now **not settable in YAML**. `PatternDef` and
`IdentityPattern` reject any value other than 1.0, so a pack author cannot encode
a hunch as a number that would then travel through the system looking like
evidence. If fractional deterministic confidence is ever genuinely needed, that
is a new ADR.

Every existing P1 confidence test passes unchanged. The evidence invariant is
checked before the confidence invariant, so a field missing both still reports
the missing citation first — the more fundamental failure and the more useful
message.

## Eight canonical fields

Each is extractable **and verifiable** from `corpus/cisco/dev/`. The two files
disagree on five of the eight, which is what makes them worth testing against.

| Field | rtr-core-01 | sw-access-02 |
| --- | --- | --- |
| `ssh_version` | 2 (L12) | UNKNOWN — absent |
| `telnet_enabled` | false (L38) | **true** (L17) |
| `http_server_enabled` | false (L13) | false (L7) |
| `https_server_enabled` | true (L14) | UNKNOWN — absent |
| `idle_timeout_seconds` | 600 (L39) | 1800 (L18) |
| `logging_hosts` | 1 host (L16) | 1 host (L9) |
| `ntp_servers` | 2 servers (L19-20) | 1 server (L10) |
| `banner_present` | true (L22) | UNKNOWN — absent |

`idle_timeout_seconds` is the case scoping exists for: rtr-core-01 line 36 is
`exec-timeout 0 0` under `line con 0`, and it must not become the management
idle timeout.

### Five canonical fields deliberately not implemented

`aaa_enabled`, `min_password_length`, `snmp_v3_only`, `weak_ciphers` have **no
occurrence in either development file**. Patterns could be written from general
Cisco knowledge but not verified, and an unverified pattern that silently never
matches is worse than an absent one: the field looks supported while producing
UNKNOWN forever.

`logging_enabled` is different and worth naming separately. It could be derived
from `logging_hosts` being non-empty — but that is inference, not extraction, and
inference belongs to the rule engine at P6 where it can be stated declaratively
and cited. Deriving it in the parser would smuggle a judgement into a layer that
is supposed to have none.

## Abstention

Uniform rules; no field has a special case.

| Situation | Result |
| --- | --- |
| Pattern declared, nothing matched | UNKNOWN, `NO_MATCH` |
| Pack declares no pattern | field omitted entirely |
| One match, or several agreeing | PRESENT, every citation kept |
| Several matches disagreeing | UNKNOWN, `CONFLICTING_EVIDENCE`, **all** citations kept |
| Multi-valued (`cast: list`) | PRESENT, values accumulate |
| Cast failed | no fact — no plausible substitute |

Key presence distinguishes "the directive is absent from this configuration",
which P5 resolves against a platform default, from "we cannot parse this
control", which routes to training. Both read UNKNOWN through `state_of()`.

A disagreement is not a tie to be broken by position. Two lines saying different
things is a configuration we cannot read confidently, and the field abstains
carrying both citations so an operator can see exactly what we could not resolve.

## Consequences

`api/parse/` may not import `api/learn/`, `api/comply/`, `api/remediate/`,
`api/normalise/`, any ML library or any network client — all asserted. The parser
produces facts; whether a fact is secure is decided at P6 by an engine that
cannot import this package.

The corpus is two Cisco devices. That is enough to author and verify eight
fields; it is **not** enough to validate compliance rules. See
`docs/CORPUS_PREREQUISITES.md`.
