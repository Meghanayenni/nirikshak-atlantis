# ADR 0004 — NIRIKSHAK-owned hierarchical block parser

- **Status:** Accepted
- **Date:** 2026-08-26
- **Decision reference:** R4
- **Affects:** `api/parse/`, the data contracts, P4

## Context

The specified deterministic parsing stack is TextFSM with `ntc-templates`. That
combination targets the output of `show` commands: flat, tabular,
record-oriented text.

Running configurations are not that shape. They are hierarchical:

- Cisco IOS, NX-OS and Arista EOS use significant indentation beneath
  `interface`, `line vty` and similar block headers.
- Juniper JunOS uses either brace nesting or flat `set` paths.
- PAN-OS exports as XML, or as flat `set` paths.

TextFSM has no block model. The line `exec-timeout 10 0` means nothing without
knowing which block encloses it — read under `line vty 0 4` it is a management
idle timeout, read under `line con 0` it is a different control entirely.

Since deterministic parsing is the foundation the whole system rests on, a gap
here propagates into every verdict.

## Decision

Build a small, deterministic, NIRIKSHAK-owned **block parser** that converts a
flat configuration file into a `ConfigTree` before any pattern runs.

`ciscoconfparse` is **not** introduced unless a concrete requirement appears
that our parser cannot reasonably support.

The parser must preserve **parent/child context** and **exact source evidence**.

## Design

Four syntax modes:

| Mode       | Structure                    | Platforms                    |
| ---------- | ---------------------------- | ---------------------------- |
| `indent`   | significant leading whitespace | Cisco IOS, NX-OS, Arista EOS |
| `brace`    | `{ }` nesting                | JunOS curly, F5              |
| `set_path` | flat `set a b c value` paths | JunOS set, PAN-OS set        |
| `xml`      | delegated to `lxml`          | PAN-OS XML exports           |
| `json`     | delegated to stdlib `json`   | cloud security-group exports |

Every `ConfigNode` carries `line_number`, `raw_line`, `parent_id`, `children`
and `block_path`, so an `Evidence` object is produced directly from a node with
no further lookup.

### Invariants, each a test

1. **Lossless** — concatenating `raw_line` over every node in source order
   reproduces the input exactly, modulo line endings.
2. **Evidence** — every node yields a complete `Evidence` object.
3. **Total** — every input line is either a node or listed in `unplaced`.
   Silent loss is impossible by construction.
4. **Deterministic** — same bytes in, same tree out.

## Consequences

**Invariant 1 does more work than it appears to.** Losslessness is what makes
the evidence claim in Rule 2 verifiable rather than asserted. If the tree can
round-trip to the original bytes, then every `line_number` and `raw_line` in
every piece of evidence in the entire system is provably real source text. One
property test at the bottom of the stack underwrites an audit-wide guarantee at
the top.

Patterns in vendor packs gain a `scope.block` selector, so a pattern can require
a node's enclosing chain to match before it applies.

**Known candidate for the escalation clause,** recorded now so it is recognised
if it arrives: banner and certificate blocks with free-form delimited bodies
(`banner motd ^C … ^C`), where the body is not structured configuration at all.
The intended answer is a declared literal-block mode in our parser rather than a
new dependency. If that proves harder than expected it will be raised
explicitly rather than resolved quietly.
