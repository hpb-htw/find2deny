# Makefile defines some common tasks which often used during development
#

version = 0.1.1
compile = python3 setup.py sdist bdist_wheel
python_files = $(shell find find2deny -name "*.py")

.PHONY: dev-release
dev-release: dev-compile
	python -m twine upload --repository-url https://test.pypi.org/legacy/ dist/*

.PHONY: dev-compile
dev-compile: $(python_files)
	echo $(version)-`date "+%s"` > __version__
	$(compile)

.PHONY:release
release: compile
	python3 -m twine upload dist/*

.PHONY: compile
compile: $(python_files)
	echo $(version) > __version__
	$(compile)

.PHONY: local-install
local-install: venv/bin/find2deny-cli

venv/bin/find2deny-cli: $(python_files) __version__
	echo $(python_files)
	pip install -e .

__version__:
	echo $(version)-`date "+%s"` > __version__

.PHONY: unittest
unittest:
	python3 -m pytest

.PHONY: clean-pyc
clean-pyc:
	find . -type f -name "*.py[co]" -delete -or -type d -name "__pycache__" -delete

.PHONY: clean
clean: clean-pyc
	rm -rf .eggs .pytest_cache find2deny.egg-info dist build __version__
	rm -f venv/bin/find2deny-cli



# Auxiliary target
.PHONY: setup-dist-tool
setup-dist-tool:
	python -m pip install setuptools wheel twine


