"""Constructed remediation snippets for tests.

**None of these is a real remediation and none may ever be shipped.** The
`snippets/` library is empty because no vendor documentation has been sourced
(decision D27), and that is the state the repository is in.

These exist to exercise the loader, the resolver and the ordering logic, which
are real code that must be correct before there is anything for them to act on -
the same division P7 used for ACL fixtures (decision D21).

Three properties keep them from being mistaken for the real thing:

  * the vendor is `fixture-os`, which is not a platform NIRIKSHAK detects;
  * `vetted_by` says explicitly that nobody vetted them;
  * `reference` says explicitly that no document was consulted.

The commands are deliberately **not** plausible device syntax. A test fixture
containing `transport input ssh` would be one careless copy-paste away from
becoming a shipped snippet, and would look exactly like a vetted one in a diff.
"""

from __future__ import annotations

from api.models.enums import LockoutRisk
from api.models.snippet import ImpactAssessment, RemediationSnippet

FIXTURE_VENDOR = "fixture-vendor"
FIXTURE_OS_FAMILY = "fixture-os"

NOT_VETTED = "NOBODY - constructed test fixture, not vetted"
NO_DOCUMENT = "none - constructed test fixture, no vendor document was consulted"


def snippet(
    snippet_id: str,
    *,
    rule_id: str = "NRK-FIXTURE-001",
    vendor: str = FIXTURE_VENDOR,
    os_family: str = FIXTURE_OS_FAMILY,
    commands: tuple[str, ...] = ("fixture-command-alpha",),
    rollback: tuple[str, ...] = (),
    depends_on: tuple[str, ...] = (),
    order_hint: int = 100,
    lockout_risk: LockoutRisk = LockoutRisk.NONE,
    service_affecting: bool = False,
    notes: str | None = None,
) -> RemediationSnippet:
    """One constructed snippet. Every default is inert."""
    return RemediationSnippet(
        snippet_id=snippet_id,
        rule_id=rule_id,
        vendor=vendor,
        os_family=os_family,
        commands=commands,
        rollback=rollback,
        depends_on=depends_on,
        order_hint=order_hint,
        impact=ImpactAssessment(
            service_affecting=service_affecting,
            lockout_risk=lockout_risk,
            notes=notes or ("constructed fixture" if lockout_risk is LockoutRisk.HIGH else None),
        ),
        vetted_by=NOT_VETTED,
        reference=NO_DOCUMENT,
    )


SNIPPET_YAML = """\
snippet_id: fixture-alpha
rule_id: NRK-FIXTURE-001
vendor: fixture-vendor
os_family: fixture-os
commands:
  - fixture-command-alpha
vetted_by: NOBODY - constructed test fixture, not vetted
reference: none - constructed test fixture, no vendor document was consulted
"""
"""The smallest file that loads, for tests that must write one to disk.

Written into a tmp_path, never into `snippets/`. A test that dropped a file into
the real library would make `test_the_snippet_library_is_empty` fail for a reason
that has nothing to do with sourcing.
"""
