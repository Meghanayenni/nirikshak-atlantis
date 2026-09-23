# Corpus provenance

Every configuration under `corpus/` is **synthetic**: written by Team Atlantis to
be realistic, not captured from a real network. None is real-world configuration
data and none may be represented as such. `corpus/MANIFEST.yaml` records the
machine-checked form of this — split, checksum, vendor, sanitisation — and
`tests/integration/test_corpus_policy.py` enforces it.

This document exists because nine files added at P15 cite `corpus/PROVENANCE.md`
in their own headers, and the file did not exist. A dangling provenance
reference is worse than none: it implies a source list somebody could check.

---

## What this file records, and what it does not

It records **what each configuration declares about itself**, transcribed from
the header the file carries.

It is **not a bibliography.** The headers say command syntax was "adapted from"
named vendor documentation, but no document identifier, edition or locator was
supplied with the files. Per `docs/CONTENT_POLICY.md` a citation is an
identifier and a locator; a vendor's name alone is neither.

**So no claim in this file should be read as a verified citation.** The
distinction matters most for `docs/SOURCING_BACKLOG.md` gap 2: a corpus file can
never establish what a vendor documents as a default, whatever its header says,
and a test asserts that no platform default cites a corpus path.

---

## Declared sources, by file

| File | Declares its syntax adapted from |
| --- | --- |
| `cisco/dev/edge-rtr-01.cfg` | Cisco SSH/AAA/SNMPv3 and hardening configuration guides, plus community configuration examples |
| `cisco/dev/branch-rtr-07.cfg` | Public Cisco IOS hardening documentation |
| `cisco/dev/dist-sw-03.cfg` | Public Cisco IOS hardening documentation (Catalyst switch form) |
| `cisco/dev/edge-rtr-09.cfg` | Public Cisco IOS documentation; built to exercise absence semantics |
| `cisco/eval/edge-rtr-11.cfg` | Regression fixture; every command shape already appears in a development file |
| `cisco/dev/dc1-leaf-01.cfg` | Cisco NX-OS configuration guides and the NX-API DME/CLI reference |
| `arista/dev/dc1-spine-01.cfg` | Arista EOS User Manual — Connection Management, Session Management, eAPI chapters |
| `juniper/dev/core-rtr-01.conf` | JunOS CLI User Guide and Juniper's published firewall-filter examples (brace-nested form) |
| `juniper/dev/edge-rtr-02.conf` | JunOS CLI User Guide and the SNMPv3 USM/VACM configuration reference (flat `set` form) |

Files added before P15 declare no per-file source and are recorded in the
manifest as *"hand-written by Team Atlantis in the style of public vendor
documentation"*.

---

## Sanitisation

RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and RFC 1918
addressing only. Hostnames use RFC 2606 reserved domains.

**No credential in any form**, including a hashed one — a type-7 or MD5 hash is
crackable, so a file containing one is not sanitised. Where a configuration needs
a credential-shaped value to exercise a check, it carries a literal placeholder
that is not a hash of anything: `$9$SAMPLE$PlaceholderEnableHash…NotARealSecret`
recovers to no secret because there is none behind it.

Two files were modified at registration. `cisco/dev/dist-sw-03.cfg` and
`arista/dev/dc1-spine-01.cfg` each carried an invented SNMP v2c community string.
A non-default community **is** a shared secret regardless of how it was chosen,
so both were rewritten to `public` — the published default, which is the finding
being tested rather than a secret. The property each fixture exists to exercise
(a v2c community present, so `snmp_v3_only` must be FALSE) is unchanged.

---

## A naming coincidence worth recording

`dc1-leaf-01.cfg` is **Cisco NX-OS**. `dc1-spine-01.cfg` is **Arista EOS**. The
names pair as though they were one fabric from one vendor, and the second was
very nearly registered as NX-OS on that assumption. Each file's own header
declares its platform, and the header is the authority.
