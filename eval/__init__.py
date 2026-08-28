"""NIRIKSHAK — evaluation harness (P9).

Accuracy is reported as a measurement, not a claim.

The package is split along one line that carries the whole argument:

    corpus.py   labels.py   metrics.py     may not import the pipeline
    score.py    report.py   run.py         run the pipeline and compare

Ground truth is loaded by modules that have no route to a parser, a normaliser
or a compliance engine, so a label cannot be produced by the thing it scores.
An architecture test asserts the boundary rather than trusting it.
"""
