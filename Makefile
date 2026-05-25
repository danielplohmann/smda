PYTHON ?= python3

init:
	$(PYTHON) -m pip install --upgrade pip "setuptools>=64.0.0,<82.1.0" "wheel>=0.47.0,<0.48.0"
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
