init:
	pip install -r requirements.txt
	pre-commit install
package:
	rm -rf dist/*
	python setup.py sdist
publish:
	python -m twine upload dist/* -u __token__
pylint:
	python -m pylint --rcfile=.pylintrc smda
ruff-check:
	ruff check .
ruff-format:
	ruff format .
ruff-fix:
	ruff check . --fix
lint: ruff-check
format: ruff-format
test:
	pytest tests/test*
test-coverage:
	python -m nose --with-coverage --cover-erase --cover-html-dir=./coverage-html --cover-html --cover-package=smda
clean:
	find . | grep -E "(__pycache__|\.pyc|\.pyo$\)" | xargs rm -rf
	rm -rf .coverage
	rm -rf coverage-html
	rm -rf dist/*
