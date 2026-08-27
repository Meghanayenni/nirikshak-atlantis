# Vetted remediation snippets

**This library is empty, and that is its current correct state.**

DEVELOPER_GUIDE.md Rule 4: remediation commands come from here and from nowhere else.
There is no generation path in the loader, the resolver or the report. A rule
with no snippet produces no command — not an improvised one.

---

## Why it is empty (decision D27)

A snippet may only be added once someone has **read a vendor document and
checked the commands against it**. `vetted_by` and `reference` are both
mandatory, in the contract and in the JSON schema, precisely so that a snippet
cannot be added without naming who checked it and what they checked it against.

No vendor documentation has been sourced for this project. Writing
`transport input ssh` from general knowledge would produce a command that is
probably right, attributed to nobody, checked against nothing — pasted by an
operator into a production device on NIRIKSHAK's authority. That is the single
most damaging output this system could produce, so the empty state is preferred
to a plausible one.

This is the same refusal that leaves `frameworks: []` on every rule and zero
platform defaults in every pack. See `docs/SOURCING_BACKLOG.md` gap 6.

## What the operator sees instead

Every FAIL in every report carries this sentence, and it is not suppressible:

> No vetted remediation is available for this platform and rule.

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
   and `test_the_snippet_library_is_empty` will fail deliberately so the change
   is a decision rather than an accident.

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

That ordering is implemented and unit-tested against constructed fixtures. It
has never ordered a real snippet, because there are none.
