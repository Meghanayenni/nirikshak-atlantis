# ADR 0066 — An example carries its block

- **Status:** Accepted
- **Date:** 2026-09-27
- **Phase:** P18
- **Decisions:** D166 (a seed from a block-scoped pattern is offered only for a
  cluster whose every line sits inside that block)
- **Affects:** `api/learn/index.py`, `api/learn/suggest.py`, `api/train/queue.py`

## Context

ADR 0064 recorded it: pattern examples become similarity-index seeds, and a seed
carried its text but not its block. The EOS pattern `^no shutdown$` means telnet
is enabled only under `management telnet`, yet its seed ranked `telnet_enabled`
first at cosine 1.0 for every unknown `no shutdown` — under interfaces, under
`management ssh`, under `management api http-commands`. A training screen is
where a careless confirmation enters a pack permanently (DEVELOPER_GUIDE.md §10), and
this put a wrong answer at the top of it with a perfect score.

## D166 — the scope travels with the example

`IndexEntry.scope` holds the pattern's block regexes. Ranking takes the block
paths of the lines being asked about and drops a scoped example unless **every**
path is inside its scope. Every, not any: a cluster groups lines by shape across
blocks, and one confirmation applies to all its members, so an example that
fits some of them would teach the pack something false about the rest.

Two things are deliberately not restricted:

- **Root-scoped seeds.** A root-level line names its own meaning. Restricting
  it to root would stop a Cisco seed from ever being offered for a JunOS line,
  which is the cross-vendor retrieval the layer exists for.
- **Administrator confirmations.** They record no block, so they carry none.

No score floor is added; `MIN_SCORE` stays 0.0 for the reason written beside it.

## Measured, with the model installed

| Query `no shutdown`, located in | Rank 1 |
| --- | --- |
| nowhere (as before this change) | `telnet_enabled`, Arista seed, **1.000** |
| `interface Ethernet1` | `telnet_enabled`, NX-OS seed `no feature telnet`, 0.227 |
| dc1-spine-01's real cluster (lines 38, 46, 48, 81, 87) | same, 0.227 |
| `management telnet` | `telnet_enabled`, Arista seed, 1.000 |

The Arista seed is gone outside its block, and the best remaining score is
0.227. **Rank 1 is still labelled `telnet_enabled`**, from an unrelated
root-level NX-OS seed at 0.227. It is a weak neighbour, shown as a ranking and
not a probability, and removing it would take either a score floor (declined
until a calibrator exists, D42) or a vendor-aware restriction on root seeds,
which is a separate decision.
