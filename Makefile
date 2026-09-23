# NIRIKSHAK — development tasks
#
# On Windows the venv binaries live in .venv/Scripts; elsewhere in .venv/bin.
ifeq ($(OS),Windows_NT)
	VENV_BIN := .venv/Scripts
else
	VENV_BIN := .venv/bin
endif

PY     := $(VENV_BIN)/python
PIP    := $(VENV_BIN)/pip
PYTEST := $(VENV_BIN)/pytest
RUFF   := $(VENV_BIN)/ruff

.PHONY: help venv install install-report install-ai install-supply test lint fmt run migrate \n        verify-audit evaluate sbom audit openapi supply-chain verify clean

help:
	@echo "venv            Create the project-local Python 3.11 virtual environment"
	@echo "install         Install core + dev dependencies (P0)"
	@echo "install-report  Optional PDF rendering (needs system GTK3; HTML needs neither)"
	@echo "install-ai      Similarity layer deps (P10; weights are a separate step)"
	@echo "test            Run the test suite"
	@echo "sbom            Regenerate docs/sbom.cdx.json from requirements.lock"
	@echo "audit           pip-audit the locked dependencies (fails on a known advisory)"
	@echo "openapi         Regenerate docs/openapi.json from the live app"
	@echo "supply-chain    sbom + openapi + audit"
	@echo "verify          lint + test + supply-chain — what CI should run"
	@echo "lint            Run ruff checks"
	@echo "fmt             Format with ruff"
	@echo "migrate         Apply pending database migrations"
	@echo "verify-audit    Verify the audit hash chain (tamper-evident)"
	@echo "evaluate        Score against hand-authored ground truth (P9)"
	@echo "run             Start the API with reload"
	@echo "clean           Remove caches and build artefacts"

venv:
	py -3.11 -m venv .venv

install:
	$(PIP) install -e ".[dev]"

install-report:
	$(PIP) install -e ".[report]"

install-ai:
	$(PIP) install -e ".[ai]"

install-supply:
	$(PIP) install -e ".[supply]"

test:
	$(PYTEST)

# --- Supply chain ----------------------------------------------------------
#
# The SBOM is built from requirements.lock, NOT from the virtual environment.
# An environment SBOM describes one developer's machine -- ours currently holds
# 119 packages including the tools that produced it -- while the lock file is
# the closure this project actually declares. A bill of materials for a laptop
# is not a bill of materials for a product.

sbom:
	$(VENV_BIN)/cyclonedx-py requirements requirements.lock 		--of JSON --output-reproducible -o docs/sbom.cdx.json

# Exits non-zero when a locked dependency has a known advisory, and it does
# today: see the supply-chain note in README.md. Kept OUT of `make test` on
# purpose -- a third-party CVE is not a test failure, and wiring it there would
# make every unrelated change look broken while teaching everyone to ignore a
# red build. It is in `verify`, where it can be read as what it is.
audit:
	$(VENV_BIN)/pip-audit --requirement requirements.lock --strict

openapi:
	$(PY) -c "import json, pathlib; from api.main import app; 	pathlib.Path('docs/openapi.json').write_text(json.dumps(app.openapi(), indent=2, sort_keys=True) + chr(10), encoding='utf-8'); 	print('docs/openapi.json regenerated')"

supply-chain: sbom openapi audit

verify: lint test sbom openapi audit

lint:
	$(RUFF) check .

fmt:
	$(RUFF) format .

migrate:
	$(PY) -c "from api.db.connection import connect; from api.db.migrate import migrate; from api.config import settings; c=connect(settings.db_path); print([m.name for m in migrate(c)] or 'already current')"

verify-audit:
	$(PY) scripts/verify_audit_chain.py

# Scores the evaluation split against corpus/labels/. Exits non-zero only when
# the measurement cannot be made honestly, never because a number is low.
evaluate:
	$(PY) -m eval.run --out

run:
	$(VENV_BIN)/uvicorn api.main:app --reload

clean:
	$(PY) -c "import shutil, pathlib; [shutil.rmtree(p, ignore_errors=True) for p in pathlib.Path('.').rglob('__pycache__')]"
	$(PY) -c "import shutil; [shutil.rmtree(d, ignore_errors=True) for d in ('.pytest_cache', '.ruff_cache', 'htmlcov')]"
