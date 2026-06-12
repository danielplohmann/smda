PYTHON ?= python3

.PHONY: init package publish ruff-check ruff-format ruff-fix lint format test test-coverage clean benchmark profile-cpu profile-mem profile-flame

# Default profiling target fixture; override e.g. `make profile-cpu TARGET=komplex`
TARGET ?= asprox

init:
	$(PYTHON) -m pip install --upgrade pip "setuptools>=64.0.0,<82.1.0" "wheel>=0.47.0"
	$(PYTHON) -m pip install -e ".[dev]"
	$(PYTHON) -m pre_commit install
package:
	rm -rf dist/*
	$(PYTHON) -m build --no-isolation
publish:
	$(PYTHON) -m twine upload dist/* -u __token__
ruff-check:
	$(PYTHON) -m ruff check .
ruff-format:
	$(PYTHON) -m ruff format .
ruff-fix:
	$(PYTHON) -m ruff check . --fix
lint: ruff-check
format: ruff-format
test:
	$(PYTHON) -m pytest tests/test*
test-coverage:
	$(PYTHON) -m pytest --cov=smda --cov-report=html:coverage-html tests/
benchmark:
	$(PYTHON) .github/workflows/scripts/run_perf_check.py --output benchmark_results.json
profile-cpu:
	$(PYTHON) -m profiling.profile_smda cpu --target $(TARGET) --line
profile-mem:
	$(PYTHON) -m profiling.profile_smda mem --target $(TARGET)
# py-spy needs sudo on macOS, and --native is Linux-only (see profiling/README.md).
profile-flame:
	py-spy record --native -o profiling/output/$(TARGET).cpu.svg -- \
		$(PYTHON) -m profiling.profile_smda run --target $(TARGET)
clean:
	find . | grep -E "(__pycache__|\.pyc|\.pyo$\)" | xargs rm -rf
	rm -rf .coverage
	rm -rf coverage-html
	rm -rf dist/*
