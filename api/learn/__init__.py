"""NIRIKSHAK - the similarity layer (P10).

The one advisory branch in a deterministic system. It proposes mappings for
configuration lines no vendor pack recognises; it never decides anything.

    cluster.py     group unknown lines by token shape - deterministic
    signature.py   the token shape itself - pure string handling
    embedding.py   the model adapter, behind an availability probe
    index.py       labelled examples, seeded from development packs only
    suggest.py     top-3 retrieval, and the gate that keeps a score a score
    calibration.py the machinery, and the refusal to fit one yet

Every suggestion leaves this package as UNCALIBRATED_SIMILARITY, which forces
the field to UNKNOWN. Nine forbidden import edges mean nothing here can reach a
verdict, a canonical field, a remediation command or a report. Coverage grows
one way: an administrator confirms, the mapping becomes a pack pattern, and the
next parse matches it deterministically.
"""
