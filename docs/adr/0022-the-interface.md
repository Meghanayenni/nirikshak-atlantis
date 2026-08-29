# ADR 0022 — The interface, and what it refuses to draw

- **Status:** Accepted
- **Date:** 2026-08-29
- **Phase:** P13
- **Decisions:** D58 (light theme, per the specification), D59 (counts, not a
  compliance percentage), D60 (no charting dependency), D61 (no device lifecycle
  actions), D62 (drift is not implemented in the browser)
- **Defects:** none fixed, none introduced. DEF-3 and DEF-8 remain open.
- **Related:** ADR 0014 (the UI is P13), ADR 0015 (`ui_reference.html` is the
  specification), ADR 0019 (the training GUI is P13's), ADR 0021 (P12 abstains)

## Context

Four ADRs and the README have deferred the interface to this phase, and
`docs/ui_reference.html` has been its specification since P8. That file contains
six sections — tokens, verdict and severity, fleet, device, finding, training —
which is the screen set, and DEVELOPER_GUIDE.md §10 supplies the build order:

> Build the finding detail view before any dashboard — it is the atom of the
> product; everything else is composition.

**The reference is a visual specification containing illustrative data.** It
draws `CIS 1.2.3 · NIST AC-17 · STIG V-215807`, a 62% compliance figure, `CAT I`
severities, IP addresses and a complete `transport input ssh` remediation block.
None of that exists in this backend. The existing guard
`test_the_ui_reference_is_untouched_by_the_backend` explains why it must not:
*"rendering any of it would ship those values."*

So P13 translates the reference's **structure and visual language**, and none of
its data. That distinction is the whole phase.

## What was built

A React 18 + TypeScript + Vite + Tailwind application in `ui/`, consuming the
existing API and adding nothing to it. **No backend file was changed.**

| Layer | Contents |
| --- | --- |
| `types/api.ts` | Contracts derived by calling all 28 endpoints and reading the responses |
| `services/` | One `fetch` wrapper plus nine domain modules; no component fetches |
| `hooks/` | `useApi`, `useMutation`, auth and toast context |
| `components/` | Verdict vocabulary, evidence viewer, remediation and prioritisation panels, primitives |
| `pages/` | 18 screens across shared, admin and capability-limited groups |

The four screens the reference specifies — fleet, device, finding, training —
were built first and in that order.

## D58 — the light theme, as specified

An earlier draft of this phase began in dark navy on a later instruction. That
was **reverted**: `ui_reference.html` §1 and DEVELOPER_GUIDE.md §10 define an exact light
palette, and the project owner confirmed the light direction is authoritative.
The tokens in `tailwind.config.js` are now the reference's own values.

§10 permits token revision — *"component styling are implementation choices
living in the frontend as tokens"* — but the principles it protects are not
revisable, and all of them survive intact:

- **FAIL is heaviest**: solid fill, reversed text, semibold, drawn first.
- **PASS is lightest**: a tint. A compliant control needs no attention.
- **UNKNOWN is dashed neutral slate, deliberately not amber.** Abstention sits
  off the severity axis, not at the bottom of it. A test asserts the chip carries
  `border-dashed`, carries the `unknown` token, and carries neither `inferred`
  nor `amber` — because if the interface made abstention look like a weaker
  failure, operators would learn to filter it out and Rule 3 would be defeated at
  the presentation layer.
- **INFERRED has its own marker and no way to suppress it.** The component takes
  no props; a test asserts `InferredMarker.length === 0`.
- **Colour never carries meaning alone**: every chip pairs its colour with a
  glyph and a text label, so the interface survives greyscale and colour vision
  deficiency.
- **Severity is ink weight and a bar**, never a second colour scale.

## D59 — counts, not a compliance percentage

The reference shows `62%` per device. The backend returns verdict counts, and any
single ratio would have to hide one of three states: `pass/(pass+fail)` conceals
abstentions, `pass/total` makes an abstention look like a failure.

So every screen shows **counts** — `7 pass · 0 fail · 0 unknown` — with UNKNOWN
keeping its own column. A single number cannot carry three-valued logic honestly,
and inventing one to fill a tile would undo the distinction the whole engine is
built on. A test asserts no `%` appears in the verdict display.

## D60 — no charting dependency

§10: *"No chart that a sentence or a sorted table would carry better. No
decorative visualisation of pass/fail ratios."* A dashboard donut of pass/fail is
exactly the named anti-pattern, and there is no time series in this system to
plot. Recharts was removed from the dependency list before it entered the
lockfile. Metric tiles and sorted tables carry the dashboard.

## D61 — no device lifecycle actions

Quarantine, disable and remove were requested. **The API exposes no device
lifecycle endpoint**, and adding one is backend work outside a frontend phase.

A button that appeared to quarantine a device and did nothing would be the worst
failure this interface could have: it would report an outcome that never
happened, about the one thing the operator was watching. So the fleet table has
no such actions, and `services/devices.ts` says in its own docstring why there is
no function for them.

The confirmation-dialog component *is* built, and guards the one destructive
action that genuinely exists — `POST /users/{id}/disable`. A test asserts the
request is not sent until the dialog is confirmed.

## D62 — drift is not implemented in the browser

There is no snapshot store and no comparison endpoint. Computing drift client-side
would make the frontend a second analysis engine, capable of disagreeing with the
backend about the same estate — which is the failure the whole architecture is
shaped to prevent.

`/drift` is a page that says so and points at Prioritisation, where peer-baseline
drift (how a device differs from its cohort *now*) is a different question the
backend does answer.

## Honesty at the presentation layer

The backend has four architecture guards over its own report template. They
encode principles rather than template rules, so P13 mirrors each as a frontend
test:

| Backend guard | Frontend mirror |
| --- | --- |
| Template claims no exposure ranking | No rank column renders unless the backend ranked; the refusal and its blockers are shown instead |
| Template prints no framework identifier | Asserts no `CIS n.n`, `AC-17`, `V-2158xx` or `ISO A.n` appears anywhere in the rendered document |
| Remediation sentence comes from the resolver | No `<pre>` block exists unless the response carried commands; asserts no `transport input ssh` or `configure terminal` leaks in |
| `device_id` is never called a device identity | Devices are labelled by hostname; the page calls the hash a "configuration file id" and explains that it changes when the file is edited |

Five display states are kept distinct, and the distinction is the product:
loading, empty, **blocked**, error, and **abstained**. Collapsing *blocked* into
*empty* is DEVELOPER_GUIDE.md §14's named failure — *"a mode that silently returns empty
output is indistinguishable from a clean result"* — and on this build it would
render an empty outliers list as a uniform fleet.

## Security

Role checks in the router are **UX controls, not security**, and the code says so
where a reader will find it. The backend refuses independently: admin endpoints
answer 403, and a resource owned by somebody else answers 404 rather than 403 so
nothing is learned about which ids exist. Verified live: `/fleet/baseline` and
`/training/queue` return 403 to a user and 200 to an admin, through the same
proxy the browser uses.

Credentials are HTTP Basic (D25) held in `sessionStorage` — tab-scoped, cleared
when the tab closes. `localStorage` would persist indefinitely on a shared
machine. This is a real limitation of Basic auth and is stated in the code rather
than hidden. No secret is in the bundle, no API host is baked in, and no raw
configuration is logged to the console.

## Consequences

**Nothing measured, nothing claimed.** P13 adds no metric and no accuracy figure.
It is a rendering layer over contracts that already existed.

**Integration gaps found and recorded, not papered over:** prioritisation is
returned on the audit *response* and never persisted, so it cannot be read back
for a past run; there is no fleet-wide findings endpoint, so the findings page
composes from the runs the caller can see; there is no vendor-pack listing
endpoint, so that page shows the versions recorded on audit runs and says so.

**Not built at P13:**

- Any backend endpoint, adapter or schema change.
- Drift detection, device lifecycle actions, public sign-up, profile editing —
  each has no backing capability, and each says so on its own page.
- Any fix to DEF-3 or DEF-8, which remain open and untouched.
