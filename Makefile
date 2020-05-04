init:
	pip install -r requirements.txt
pylint:
	python3 -m pylint --rcfile=.pylintrc smda
test:
	python3 -m nose
test-coverage:
	python3 -m nose --with-coverage --cover-erase --cover-html-dir=./coverage-html --cover-html --cover-package=smda
clean:
	find . | grep -E "(__pycache__|\.pyc|\.pyo$\)" | xargs rm -rf
	rm -rf .coverage
	rm -rf coverage-html
	rm -rf dist/*