# ADR 0001 — No live device access; Netmiko and NAPALM removed

- **Status:** Accepted
- **Date:** 2026-08-26
- **Decision reference:** R1
- **Affects:** dependency set, `api/parse/`, `tests/architecture/`

## Context

`DEVELOPER_GUIDE.md` §10 and Concept Report §7 both list Netmiko and NAPALM in the
technology stack. Both documents also forbid live device access without
qualification:

- `DEVELOPER_GUIDE.md` §9 — "DO NOT implement: live device access, active network
  scanning".
- Concept Report §5 — "No live device access or network scanning. Offline
  configuration exports only. This keeps the deployment footprint minimal and
  requires no credentials."

This is a direct contradiction. Netmiko is an SSH connection library; NAPALM is
a device-driver abstraction. Connecting to equipment is their purpose.

The genuinely useful, offline part of that ecosystem is the TextFSM template
collection that Netmiko bundles — and it is distributed independently as the
`ntc-templates` package, which the stack already lists separately.

## Decision

NIRIKSHAK is **configuration-file-only**. Netmiko and NAPALM are not
dependencies of this project.

Offline parsing is provided by:

- `textfsm` — template parsing of flat, record-shaped output
- `ntc-templates` — the template corpus itself
- the NIRIKSHAK block parser (ADR 0004) — hierarchical configuration structure
- `lxml` — XPath over XML exports

## Consequences

**Enforced, not merely observed.** Two independent mechanisms:

1. `ruff` banned-import configuration in `pyproject.toml` — fails in the editor,
   before CI is reached.
2. `tests/architecture/test_no_device_libraries.py` — checks both that no source
   file under `api/` imports such a library, *and* that none is present in the
   resolved environment. A third test proves the detector actually fires against
   a planted violation, so the guardrail cannot pass vacuously.

Banned: `netmiko`, `napalm`, `paramiko`, `scrapli`, `ncclient`, `pysnmp`,
`telnetlib`, `asyncssh`.

**The guarantee is now structural.** A library that is not installed cannot be
called by a future contributor in a hurry. No schema in the project carries a
credential field or a connection target, so there is nothing for such code to
use even if it were written.

**Trade-off accepted.** The project cannot fetch a configuration from a device
for the operator. This is the intended behaviour: the operator exports
configurations by their own means, and NIRIKSHAK requires no credentials at all.
