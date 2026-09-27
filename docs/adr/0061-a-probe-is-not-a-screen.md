# ADR 0061 — A probe is not a screen

- **Status:** Accepted
- **Date:** 2026-09-27
- **Phase:** P18
- **Decisions:** D151 (the interface has no capability-status screen; `GET /health`
  remains the answer to that question)
- **Affects:** `ui/src/pages/Status.tsx` (removed), `ui/src/services/health.ts`
  (removed), `ui/src/App.tsx`, `ui/src/layouts/navigation.ts`,
  `ui/src/types/api.ts`, `ui/src/test/*`, `docs/architecture.md` §11

## Context

The drawer's *Beyond the pipeline* group ended with **Status — Installed
capabilities**: whether the embedding model's package and weights are present,
whether WeasyPrint and its native libraries load, the schema versions and the
snippet library digest, all read from `GET /health`.

Those are facts about the machine the service runs on. They matter to whoever
installs and operates it, and they are already answered where that person looks
— the endpoint, which needs no credentials, and the README's setup steps. For an
engineer auditing a fleet they answer no question at any of the three levels of
zoom (DEVELOPER_GUIDE.md §10), and the two that change what an operator can do already
surface where the operator meets them: the review queue arrives without ranked
suggestions and says why, and the PDF endpoint refuses with 503 and its reason.

A screen that serves none of the product's questions is navigation weight, and
in a drawer of seven entries it is one in seven.

## D151 — remove the screen, keep the probe

Removed: the page, its route, its drawer entry, the `getHealth` client (the page
was its only caller), the `Health` type, and the `/health` fixture and stubs in
ten UI test files. The stubs were there only because a test that renders the
shell could in principle route to the page; with no caller, a stub for an
endpoint the interface never requests would describe a dependency that does not
exist.

**Not removed:** `GET /health`, the capability probes behind it
(`api/main.py`), and every backend test of them. The question is still answered;
it is answered by the API.

A routing test now asserts `/status` renders *Page not found* and the drawer
carries no link to it. It was run against the previous code and failed there.

## Consequences

`App.tsx`'s header comment said "seven destinations" while there were eight; it
is accurate again. An operator who wants the probe results in a browser opens
`/health` on the API host.
