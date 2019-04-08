# Makefile defines some common tasks which often used during development
#

dist:
	python3 setup.py sdist bdist_wheel

deploy: dist
	python3 -m twine upload dist/*

deploy-test: dist
	python -m twine upload --repository-url https://test.pypi.org/legacy/ dist/*

clean-pyc:
	find . -type f -name "*.py[co]" -delete -or -type d -name "__pycache__" -delete

clean-all: clean-pyc
	rm -rf .eggs .pytest_cache find2deny.egg-info dist build

