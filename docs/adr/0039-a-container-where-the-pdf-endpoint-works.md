# ADR 0039 — A container where the PDF endpoint works

- **Status:** Accepted
- **Date:** 2026-09-23
- **Phase:** P17
- **Decisions:** D103 (the GTK probe is spelled per platform; the component set
  is not), D104 (a container that fails to build rather than ship a 503)
- **Affects:** `api/report/pdf.py`, `Dockerfile` (new),
  `docker-compose.yml` (new), `README.md`
- **Supersedes the environment finding in:** ADR 0006 — not its decision

## The premise this work was given, and what was actually true

The brief said: *"PDF rendering returns 503 — the GTK stack is absent on this
machine."* README said the same. ADR 0006 recorded it at P0 and again at P8.

**It is not true any more.** Probed directly:

```
weasyprint installed: True
  libpango-1.0-0    -> C:\msys64\mingw64\bin\libpango-1.0-0.dll
  … eight of eight resolved …
RENDERED 3946 bytes; magic = b'%PDF-'
```

The GTK runtime is installed here through MSYS2. The endpoint returns a PDF.

**The test suite already knew.** Four PDF tests carry
`@pytest.mark.skipif(availability().available, reason="GTK is installed in this environment")`
and have been skipping. ADR 0006 chose to keep the probe in code *"rather than
in prose so it re-runs on every request instead of describing a machine from
August"* — and that is exactly what saved this: the code stayed right while
three documents went stale around it.

### The gap that left

Every PDF test covered the **refusal**. Not one asserted that the endpoint
returns bytes, so on a machine with the runtime installed the deliverable
Problem Statement 26155 names was exercised by nothing at all. The capability
worked and no test said so, which is indistinguishable from a capability that
quietly stopped working.

`test_the_pdf_endpoint_returns_a_pdf_when_the_runtime_is_present` closes that,
mirroring the existing skip in the opposite direction.

## D103 — spell the probe per platform; keep the component set fixed

`find_library("libpango-1.0-0")` returns `None` on Linux **with Pango
installed**. It prepends `lib` and appends `.so` itself, so the Windows DLL
names ADR 0006 recorded do not name anything a POSIX loader can find.

A container would therefore have installed the entire stack and the probe would
have reported eight of eight missing, and the endpoint would have answered 503
explaining that none of them were there. **A probe that cannot see a runtime it
is standing on is worse than no probe**: it sends somebody to install what is
already installed.

So `required_libraries()` returns the platform's spelling, and the *set* stays
identical to ADR 0006's eight components — a failure message and the decision
record must still name the same things. The two lists are paired positionally
and a test checks the pairing, because two hand-written lists left to stay in
step do not.

This changes how the probe asks, not what it asks, and not what it does with
the answer. ADR 0006's decision — WeasyPrint only, no fallback, fail loudly —
is untouched.

## D104 — the build fails rather than shipping an image that 503s

`Dockerfile` installs the eight components by their Debian package names, plus
`fonts-dejavu-core`. The font is not optional: WeasyPrint with no font
installed renders a PDF of the right size containing nothing legible, which is
worse than the 503 it replaces — a file that looks like a report and is blank.

The last build step runs the probe **and then actually renders**, asserting the
output starts with `%PDF-`. A probe that passes while rendering fails is exactly
the gap this file exists to close, so checking only the probe would reproduce it
one layer up.

`docker-compose.yml` keeps both databases, the blob store and `packs/trained/`
on volumes. Configuration files are sensitive data (DEVELOPER_GUIDE.md §9) and must not
be baked into an artefact anyone might share, and trained packs are deployment
state for the same reason they are gitignored (D45). `NIRIKSHAK_AIRGAP=true` is
set: the build needs a network, the running container does not.

## What is verified, and what is not

**Not verified.** The image has not been built. The Docker CLI is installed on
this machine and the daemon is not running:

```
ERROR: failed to connect to the docker API at npipe:////./pipe/dockerDesktopLinuxEngine
```

So `Dockerfile` and `docker-compose.yml` are reviewed work, not tested work, and
this ADR says so rather than describing an intent as a result. The package names
and the probe's POSIX spellings are the parts most likely to be wrong, and the
build's own assertion is what will catch them — the first person to run
`docker compose up --build` learns immediately whether this is right, which is
the most that can honestly be arranged from here.

**Verified.** The probe change, on Windows, against the real runtime: eight
libraries resolved, a 3,946-byte PDF rendered, and the endpoint returning
`application/pdf` with `%PDF-` magic through the API. That is a capability this
repository has had for some time and has never demonstrated until now.
