# Canonical rules

**The single source of rule logic** (decision D15). Every check lives here as one
YAML file, and cross-maps itself through its own `frameworks` list. There are no
per-framework rule directories: a second place where a rule could be defined is a
second place where it could be wrong.

## Framework mappings, and only sourced ones (D16, then ADR 0035 and ADR 0052)

Every mapping a rule carries names a control that exists in an edition this
repository has obtained — NIST SP 800-53 Rev 5 (OSCAL 5.2.0), the DISA Cisco
IOS XE Router NDM STIG V3R7 (held), the CIS Cisco IOS XE 17.x Benchmark
v2.2.1 (referenced, never held) — and is checked against that edition's index
in `rules/frameworks/`. Every mapping is `project_asserted`: our judgement that
the check evidences the control, not a published crosswalk. A rule that does
not map to a sourced framework says why in `not_mapped`, including when the
answer is that nobody has read the framework for it.

Writing an identifier without having read the framework is inventing it — the
same act as inventing a vendor default. A mapping cannot produce a wrong PASS,
but it can produce a wrong *claim of coverage*.

*(Until 2026-09-27 this section said no mappings ship and every rule has
`frameworks: []` — true under D16, false since ADR 0035.)*

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

The remaining canonical fields without a rule (`aaa_enabled`,
`min_password_length`, `snmp_v3_only`, `logging_enabled`) have no parser
support, so a rule over them would abstain on every device forever while looking
supported. `weak_ciphers` will not get one: its name is a verdict, which a rule
makes and a pack must not. The offered SSH algorithms are read into
`ssh_ciphers` and `ssh_macs`, and NRK-CIPHER-001 and -002 judge them
(ADR 0062).
