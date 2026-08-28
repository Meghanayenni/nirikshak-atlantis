"""NIRIKSHAK - the Prioritise stage (P12).

    Ingest -> Parse -> Normalise -> Comply -> [Prioritise] -> Remediate -> Report

Two capabilities the Concept Report promises, and one refusal that matters more
than either.

    exposure.py   how reachable a control is - and why that cannot be told here
    baseline.py   peer-baseline outlier detection: counting, fully explainable
    service.py    the ordered remediation queue, or an honest statement of none

**Exposure needs interfaces and access lists.** This corpus has zero of both, on
every device, in every split. So every assessment is undetermined, `priority_rank`
and `exposure_score` stay `None`, and the layer names the missing input rather
than falling back to a severity sort - which DEVELOPER_GUIDE.md §7 forbids in as many
words, and which would look exactly like the working feature.

The layer reads canonical models and findings. It has no route to a verdict, a
raw configuration line, a remediation command or a model, and it may not import
`comply`, `parse`, `learn`, `train`, `remediate`, `report`, `ingest` or `db`.
"""
