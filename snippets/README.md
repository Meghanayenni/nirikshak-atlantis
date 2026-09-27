# Vetted remediation snippets

**Twenty snippets, three platforms, each naming a person and a document.**

DEVELOPER_GUIDE.md Rule 4: remediation commands come from here and from nowhere else.
There is no generation path in the loader, the resolver or the report. A rule
with no snippet produces no command — not an improvised one.

| Platform | Rules covered |
| --- | --- |
| `cisco` / `ios` | seven of ten — none for `NRK-CIPHER-001`/`-002`, `NRK-PASSWD-001` |
| `juniper` / `junos` | seven of ten — none for `NRK-CIPHER-001`/`-002`, `NRK-PASSWD-001` |
| `arista` / `eos` | six — see below |

---

## Why decision D27 was superseded

D27 kept this directory empty, and the reasoning was right: a snippet may only
be added once someone has **read a vendor document and checked the commands
against it**. `vetted_by` and `reference` are both mandatory, in the contract and
in the JSON schema, precisely so that a snippet cannot be added without naming
who checked it and what they checked it against.

What changed is not the standard but the work. Every entry here was checked
against the vendor's own command reference or configuration guide, and every
`reference` field carries that document's title and a locator into it. The
architecture test that asserted the library was empty has been replaced by
`test_every_shipped_snippet_is_attributable`, which asserts the properties the
empty state was standing in for: a human vetter, a cited document, and a
rollback behind every service-affecting change.

## The one deliberate gap

There is no `(arista, eos, NRK-SSH-001)` snippet. That rule requires SSH protocol
version 2, and EOS exposes no protocol-version setting to configure — there is no
command to vet. The resolver returns `NO_SNIPPET` and the operator reads:

> No vetted remediation is available for this platform and rule.

That is the correct output. Writing a command there to make the coverage table
look complete is the exact failure this library is built to prevent.

## Placeholders are deliberate

A command needing a site-specific value — a syslog collector, a time source,
banner wording — carries it as `<SYSLOG-COLLECTOR-IP>`, `<NTP-SERVER-IP>` or a
bracketed instruction, never a plausible default, and `preconditions` says so.
NIRIKSHAK does not know this site's collector and must not invent one: a command
that silently shipped a fleet's logs to an address nobody chose would be worse
than no command at all.

## Version bounds

Every snippet leaves `os_version_range` null. The schema documents null as "the
vetter did not bound it", which is honest, and it is also a real limit — an
operator on an old release is shown a command nobody confirmed applies to their
release. Bounding them is open work; see `docs/SOURCING_BACKLOG.md` gap 6.

## Adding one

1. Obtain the vendor document — configuration guide, command reference,
   hardening guide or release note — and read the relevant section.
2. Write the YAML below into `snippets/<vendor>/<rule_id>.yaml`. Any layout
   under `snippets/` works; the lookup key is inside the file, not in the path.
3. `reference` names the document and a locator into it. Per
   `docs/CONTENT_POLICY.md` that is an identifier and a locator only — never
   transcribed vendor prose.
4. `vetted_by` names the **person**. A model may not vet a snippet, and the
   architecture test greps for that.
5. Run the suite. `tests/architecture/test_rule_content_policy.py` validates
   every file against `schema/snippet.schema.json` and the Rule 4 invariants,
   and `test_every_shipped_snippet_is_attributable` checks that the new entry
   names a person, cites a document, and offers a way back from any
   service-affecting change.

```yaml
snippet_id: <vendor>-<rule_id>
rule_id: NRK-EXAMPLE-001
vendor: <vendor>
os_family: <os-family>
os_version_range: ">=15.0 <18.0"

commands:
  - <exactly what the operator types>
rollback:
  - <how to get back; required if service_affecting>
preconditions:
  - <what must be true first>
verification:
  - <how to confirm it took effect>

impact:
  service_affecting: false
  requires_reload: false
  lockout_risk: none      # none | low | high; 'high' requires notes
  notes: null

depends_on: []
order_hint: 100

vetted_by: <person who checked this>
vetted_at: 2026-01-01T00:00:00Z
reference: <document identifier and locator>
```

## Ordering

The resolver orders a set of snippets by dependency first, then by lockout risk
ascending, then by `order_hint`. A high-lockout-risk change is applied **last**,
after the snippets it depends on have been applied and verified — disabling an
insecure management protocol before its replacement works is how an operator
gets locked out of their own device.

That ordering is implemented, unit-tested against constructed fixtures, and now
exercised by real snippets: on Cisco IOS and Juniper Junos the telnet snippet
depends on the SSH one and carries a high lockout risk, so it is sequenced last —
after the replacement transport it relies on has been applied and verified.
