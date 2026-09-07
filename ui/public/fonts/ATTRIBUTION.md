# Bundled fonts

Both faces are vendored here rather than linked from a CDN. DEVELOPER_GUIDE.md Rule 6 is
offline-first: NIRIKSHAK must run on an operator network with no egress, and a
stylesheet that reaches a font host at page load would break that and leak the
fact that the tool is in use.

| File | Family | Licence |
| --- | --- | --- |
| `inter-latin-var.woff2` | Inter, variable 100-900, latin subset | SIL OFL 1.1 — `OFL-Inter.txt` |
| `instrument-serif-latin-400.woff2` | Instrument Serif, 400 roman, latin subset | SIL OFL 1.1 — `OFL-InstrumentSerif.txt` |

Inter carries the interface: it has true tabular figures, which §10 requires so
that columns of counts, line numbers and versions align. Instrument Serif is
used for the product wordmark and the landing headline only, and never for
anything that carries a verdict.

Latin subsets only. Retrieved from Google Fonts (`fonts.gstatic.com`).
