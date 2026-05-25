PYTHON ?= python3

.PHONY: init package publish ruff-check ruff-format ruff-fix lint format test test-coverage clean

init:
	$(PYTHON) -m pip install --upgrade pip "setuptools>=64.0.0,<75.4.0" wheel
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
clean:
	find . | grep -E "(__pycache__|\.pyc|\.pyo$\)" | xargs rm -rf
	rm -rf .coverage
	rm -rf coverage-html
	rm -rf dist/*
