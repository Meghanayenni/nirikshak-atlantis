"""Loading the vetted snippet library from disk.

Remediation is **data** (Rule 5), and it is **resolved, never generated**
(Rule 4). This module is the only thing in NIRIKSHAK that turns bytes on disk
into a `RemediationSnippet`, and it contains no path that produces a command
string from anything other than a file the operator can open and read.

Three gates, in order, and a snippet must pass all of them:

    JSON schema      the file has the right shape
    the contract     RemediationSnippet's own invariants (Rule 4, rollback)
    the library      ids are unique, dependencies exist, no cycles

The first two are per-file. The third is not visible from inside any single
file, which is why it is separate and why it runs over the whole set.

**The library is currently empty.** No vendor documentation has been sourced, so
no snippet can name the document it was checked against, so none may be written.
`snippets/README.md` records that in full. Nothing here treats empty as an error:
an empty library resolves nothing, which is the honest outcome, not a fault.
"""

from __future__ import annotations

import functools
import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator
from jsonschema import ValidationError as SchemaValidationError

from api.models.snippet import RemediationSnippet
from api.remediate.errors import SnippetLibraryError, SnippetLoadError

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SNIPPETS_ROOT = REPO_ROOT / "snippets"
SCHEMA_PATH = SNIPPETS_ROOT / "schema" / "snippet.schema.json"

EMPTY_LIBRARY_VERSION = "empty"
"""The version string for a library with no snippets in it.

A hash of nothing is a real hexadecimal number that looks exactly like a hash of
something, and a report footer reading `library e3b0c442` would suggest content
that is not there. A library that resolves nothing should say so in the one place
a reader looks to find out what it resolved against.
"""


def _load_schema() -> Draft202012Validator:
    if not SCHEMA_PATH.is_file():
        raise SnippetLoadError(f"the snippet schema is missing at {SCHEMA_PATH}")
    try:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SnippetLoadError(f"{SCHEMA_PATH.name}: invalid JSON - {exc}") from exc
    return Draft202012Validator(schema)


@functools.lru_cache(maxsize=1)
def _validator() -> Draft202012Validator:
    return _load_schema()


def snippet_files(root: Path = SNIPPETS_ROOT) -> list[Path]:
    """Every snippet file under `root`, in a stable order.

    `schema/` is excluded - it describes snippets rather than being one. Sorted
    by path so a library loads identically on every machine, which is what makes
    the library version reproducible.
    """
    if not root.is_dir():
        return []
    return sorted(p for p in root.rglob("*.yaml") if "schema" not in p.parts)


def load_snippet(path: Path) -> RemediationSnippet:
    """One snippet file, schema-checked then contract-checked.

    Both checks, in that order, because they catch different mistakes and the
    schema produces the better message for a shape error. Failures carry the
    filename: a library-wide error naming no file is nearly useless to whoever
    has to fix it.
    """
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise SnippetLoadError(f"{path.name}: invalid YAML - {exc}") from exc

    if not isinstance(raw, dict):
        raise SnippetLoadError(f"{path.name}: expected a mapping at the top level")

    try:
        _validator().validate(raw)
    except SchemaValidationError as exc:
        where = "/".join(str(p) for p in exc.absolute_path) or "(root)"
        raise SnippetLoadError(f"{path.name}: schema violation at {where} - {exc.message}") from exc

    try:
        return RemediationSnippet(**raw)
    except Exception as exc:
        raise SnippetLoadError(f"{path.name}: {exc}") from exc


def check_consistency(snippets: Iterable[RemediationSnippet]) -> list[str]:
    """Problems visible only across the whole library. Empty means clean."""
    items = list(snippets)
    problems: list[str] = []

    seen: set[str] = set()
    for snippet in items:
        if snippet.snippet_id in seen:
            problems.append(
                f"duplicate snippet_id {snippet.snippet_id!r} - a lookup would be ambiguous"
            )
        seen.add(snippet.snippet_id)

    for snippet in items:
        for dependency in snippet.depends_on:
            if dependency not in seen:
                problems.append(
                    f"{snippet.snippet_id!r} depends on {dependency!r}, which is not in the library"
                )

    problems.extend(_cycles(items))
    return problems


def _cycles(snippets: list[RemediationSnippet]) -> list[str]:
    """Dependency cycles, reported by name.

    A cycle means there is no order in which the snippets can be applied. Left
    undetected it would surface as a silently truncated ordering - the operator
    receives four commands where five were resolved, with nothing saying which
    one was dropped.
    """
    graph = {s.snippet_id: [d for d in s.depends_on if d != s.snippet_id] for s in snippets}
    state: dict[str, int] = {}  # 0 unvisited, 1 on the stack, 2 finished
    found: list[str] = []

    def visit(node: str, trail: list[str]) -> None:
        if state.get(node, 0) == 2:
            return
        if state.get(node, 0) == 1:
            cycle = trail[trail.index(node) :] + [node]
            found.append("dependency cycle: " + " -> ".join(cycle))
            return
        state[node] = 1
        for nxt in graph.get(node, []):
            visit(nxt, [*trail, node])
        state[node] = 2

    for node in sorted(graph):
        visit(node, [])
    return found


@dataclass(frozen=True)
class SnippetLibrary:
    """Every vetted snippet, indexed for lookup by `(vendor, os_family, rule_id)`.

    Frozen, and built only by `load_library`. There is deliberately no `add`,
    `put` or `register` method: a snippet enters this object by being a file that
    passed all three gates, and by no other route.
    """

    snippets: tuple[RemediationSnippet, ...]
    version: str

    @property
    def is_empty(self) -> bool:
        return not self.snippets

    def by_id(self, snippet_id: str) -> RemediationSnippet | None:
        for snippet in self.snippets:
            if snippet.snippet_id == snippet_id:
                return snippet
        return None

    def lookup(self, vendor: str, os_family: str, rule_id: str) -> RemediationSnippet | None:
        """The snippet for one platform and one rule, or `None`.

        `None` is a complete and final answer, not a prompt to try harder. There
        is no fallback to a nearby vendor, a nearby OS family or a generic
        snippet: close enough is how a command for one platform ends up pasted
        into another.
        """
        key = (vendor, os_family, rule_id)
        for snippet in self.snippets:
            if snippet.key == key:
                return snippet
        return None


def compute_version(paths: list[Path]) -> str:
    """A reproducible identifier for the library's exact content.

    The report footer records this, so a reader can tell whether two reports
    resolved remediation against the same library. Derived from file contents
    rather than mtimes, which differ on every checkout.
    """
    if not paths:
        return EMPTY_LIBRARY_VERSION

    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(path.read_bytes())
        digest.update(b"\x00")
    return digest.hexdigest()[:12]


def load_library(root: Path = SNIPPETS_ROOT) -> SnippetLibrary:
    """The vetted library, fully checked, or an exception.

    An empty directory yields an empty library rather than an error. That is the
    state the project is in, and it is a legitimate one: the resolver answers
    "no vetted remediation" for everything, which is true.
    """
    paths = snippet_files(root)
    snippets = tuple(load_snippet(path) for path in paths)

    problems = check_consistency(snippets)
    if problems:
        raise SnippetLibraryError(problems)

    return SnippetLibrary(snippets=snippets, version=compute_version(paths))


@functools.lru_cache(maxsize=1)
def _cached() -> SnippetLibrary:
    return load_library()


def load_active_library(*, use_cache: bool = True) -> SnippetLibrary:
    """Cached because a fleet report resolves against it once per finding."""
    return _cached() if use_cache else load_library()


def clear_library_cache() -> None:
    _cached.cache_clear()
    _validator.cache_clear()
