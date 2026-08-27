# Canonical rules

**The single source of rule logic** (decision D15). Every check lives here as one
YAML file, and cross-maps itself through its own `frameworks` list. There are no
per-framework rule directories: a second place where a rule could be defined is a
second place where it could be wrong.

## No framework mappings ship (decision D16)

Every rule here has `frameworks: []`.

Writing `CIS-1.2.3` or `AC-17(2)` into a rule without having read the benchmark
would be inventing an identifier — the same act as inventing a vendor default,
and no more defensible for being about a standard rather than a device. A mapping
cannot produce a wrong PASS, but it can produce a wrong *claim of coverage*, and
in an audit tool that is its own kind of failure.

So NIRIKSHAK currently evaluates its own checks and maps them to nothing. When a
benchmark edition is actually obtained, adding the mapping is a data change.
`test_no_framework_mappings_are_claimed` fails at that point, deliberately, so
the author has to look at the sourcing requirements rather than adding IDs
quietly.

**Until then no document, report or presentation may claim CIS, NIST, DISA STIG
or ISO/IEC 27001 coverage.**

## What a rule may contain

Per `docs/CONTENT_POLICY.md` and R16: framework and control **identifiers**, and
our own `title`, `rationale`, `severity` and check logic. Never transcribed
benchmark prose — the contract rejects a field shaped to hold it.

## Thresholds are project policy, not vendor knowledge

Where a rule names a number — a maximum idle timeout, a required SSH version —
that number is **NIRIKSHAK's own position**, written by the team and stated as
such in the rule's rationale. It is not attributed to any benchmark, and it is
not a claim about what any vendor documents as a default. Platform defaults are a
separate mechanism entirely, live in vendor packs, and require sourced provenance
(decision D11).

Thresholds are data. An operator who disagrees edits the YAML.

## Fields deliberately without a rule

`https_server_enabled` is parsed but unchecked. The obvious rule — require the
HTTPS server to be enabled — would fail a device that runs no web management at
all, which is the *more* secure configuration. The rule worth writing is
conditional on another field, and `CheckSpec` examines one field by design. So
the field is reported and not judged, rather than judged badly.

The remaining five canonical fields (`aaa_enabled`, `min_password_length`,
`snmp_v3_only`, `weak_ciphers`, `logging_enabled`) have no parser support, so a
rule over them would abstain on every device forever while looking supported.
