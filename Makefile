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

.PHONY: help venv install install-report install-ai test lint fmt run clean

help:
	@echo "venv            Create the project-local Python 3.11 virtual environment"
	@echo "install         Install core + dev dependencies (P0)"
	@echo "install-report  Add the PDF reporting group (P8, needs system GTK3)"
	@echo "install-ai      Add the machine-learning group (P10, large download)"
	@echo "test            Run the test suite"
	@echo "lint            Run ruff checks"
	@echo "fmt             Format with ruff"
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

test:
	$(PYTEST)

lint:
	$(RUFF) check .

fmt:
	$(RUFF) format .

run:
	$(VENV_BIN)/uvicorn api.main:app --reload

clean:
	$(PY) -c "import shutil, pathlib; [shutil.rmtree(p, ignore_errors=True) for p in pathlib.Path('.').rglob('__pycache__')]"
	$(PY) -c "import shutil; [shutil.rmtree(d, ignore_errors=True) for d in ('.pytest_cache', '.ruff_cache', 'htmlcov')]"
