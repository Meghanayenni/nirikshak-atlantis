"""The embedding adapter — sentence-transformers only, behind a probe.

The stack this needs is an optional extra with an acquisition step pip cannot
perform: `all-MiniLM-L6-v2` is fetched from the network on first use, and
NIRIKSHAK is meant to run air-gapped. That is structurally the same problem
ADR 0006 recorded for WeasyPrint and GTK, and it gets the same answer:

  * probe the environment on every call rather than assuming a machine from
    some earlier phase;
  * raise `ModelUnavailableError` naming exactly what is missing;
  * **no fallback.** Not a hash embedding, not bag-of-words, not a different
    model. A stand-in would produce rankings that look like model output and are
    not, and an administrator confirming a mapping is trusting the ranking that
    put it in front of them.

**No weights are committed to this repository** (decision D40). They are
downloaded once by a documented setup step, and `airgap` means the adapter fails
closed rather than reaching for them.

The import of `sentence_transformers` is deliberately lazy and guarded, so every
other phase — and every test that does not need a model — runs with the `[ai]`
extra uninstalled.
"""

from __future__ import annotations

import importlib.util
import os
from dataclasses import dataclass
from pathlib import Path

from api.learn.errors import ModelUnavailableError

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
"""Fixed by DEVELOPER_GUIDE.md §11. Substituting a different model would change every
score in the index and is not a decision this module may take on its own."""

EMBEDDING_DIMENSIONS = 384
"""The output width of the model above.

Recorded so an index built earlier can be checked against the model loaded now:
a dimension mismatch means the weights changed underneath a stored index, and
silently re-embedding would compare vectors from two different models.
"""

_CACHE_ENV = ("SENTENCE_TRANSFORMERS_HOME", "HF_HOME", "TRANSFORMERS_CACHE")


@dataclass(frozen=True)
class ModelAvailability:
    """Whether an embedding can be produced here, and if not, why."""

    package_installed: bool
    weights_present: bool
    airgap: bool
    searched: tuple[str, ...] = ()

    @property
    def available(self) -> bool:
        return self.package_installed and self.weights_present

    @property
    def summary(self) -> str:
        if self.available:
            return "The embedding model is available."
        reasons: list[str] = []
        if not self.package_installed:
            reasons.append("sentence-transformers is not installed")
        if not self.weights_present:
            reasons.append(f"no local weights for {MODEL_NAME}")
        return "The embedding model is unavailable: " + "; ".join(reasons) + "."


def package_installed() -> bool:
    """Whether the package is importable, without importing it.

    `find_spec` rather than a try/import, for the reason `api/report/pdf.py`
    gives about WeasyPrint: importing a half-present ML stack raises from deep
    inside its own bindings, and that message is about a missing symbol rather
    than about a missing runtime.
    """
    return importlib.util.find_spec("sentence_transformers") is not None


def _cache_roots() -> tuple[Path, ...]:
    """Where the weights would be, if they had been downloaded."""
    roots: list[Path] = []
    for variable in _CACHE_ENV:
        value = os.environ.get(variable)
        if value:
            roots.append(Path(value))
    roots.append(Path.home() / ".cache" / "huggingface")
    roots.append(Path.home() / ".cache" / "torch" / "sentence_transformers")
    return tuple(roots)


def weights_present() -> bool:
    """Whether the model is already on disk.

    Checked by looking for the model's directory rather than by attempting a
    load, so the probe stays cheap and — importantly — never triggers a download
    as a side effect of asking whether a download is needed.
    """
    slug = MODEL_NAME.replace("/", "--")
    for root in _cache_roots():
        if not root.is_dir():
            continue
        for candidate in (root, root / "hub"):
            if not candidate.is_dir():
                continue
            for entry in candidate.iterdir():
                name = entry.name
                if slug in name or MODEL_NAME.split("/")[-1] in name:
                    return True
    return False


def availability(*, airgap: bool = False) -> ModelAvailability:
    """Probe this environment. Not cached, for the reason ADR 0006 gives.

    The stack can be installed while the service is running, and a cached
    negative would keep reporting the absence of something now present.
    """
    return ModelAvailability(
        package_installed=package_installed(),
        weights_present=weights_present(),
        airgap=airgap,
        searched=tuple(str(r) for r in _cache_roots()),
    )


def require_model(*, airgap: bool = False) -> None:
    """Raise unless an embedding can honestly be produced here."""
    state = availability(airgap=airgap)
    if not state.available:
        raise ModelUnavailableError(
            package_installed=state.package_installed,
            weights_present=state.weights_present,
            airgap=state.airgap,
            model_name=MODEL_NAME,
        )


def embed(texts: list[str], *, airgap: bool = False) -> list[list[float]]:
    """Embed scrubbed configuration lines. Returns vectors, or raises.

    The only outcomes are vectors and an exception. Every caller may assume that
    a returned vector came from the model named above and from nothing else.

    **The text arriving here is already scrubbed.** `UnknownLine.raw_line_scrubbed`
    is redacted at P5 precisely because it reaches this function, and nothing in
    this module un-scrubs it (Rule 6).
    """
    require_model(airgap=airgap)

    try:
        model = _load(airgap=airgap)
    except Exception as exc:  # pragma: no cover - requires a half-installed stack
        raise ModelUnavailableError(
            package_installed=True,
            weights_present=False,
            airgap=airgap,
            model_name=MODEL_NAME,
            detail=f"the package is present but the model could not be loaded: {exc}",
        ) from exc

    # Normalised at source so retrieval is a dot product and cosine similarity
    # lands in [-1, 1] without a second pass. Deterministic on CPU in eval mode:
    # the same line must embed identically between runs, or every metric
    # computed over the index becomes unreproducible.
    vectors = model.encode(texts, normalize_embeddings=True, convert_to_numpy=True)
    return [[float(x) for x in vector] for vector in vectors]


def _load(*, airgap: bool):  # type: ignore[no-untyped-def]  # pragma: no cover - needs the extra
    """Load the model from the local cache only.

    `local_files_only` is set from `airgap`: with it enabled the loader must not
    reach the network even if the weights turn out to be absent, so the failure
    is a clean refusal rather than a hanging fetch.
    """
    from sentence_transformers import SentenceTransformer  # noqa: PLC0415

    return SentenceTransformer(
        MODEL_NAME,
        device="cpu",
        local_files_only=airgap,
    )
