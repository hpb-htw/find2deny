# Makefile defines some common tasks which often used during development
#

version = 0.1.7
compile = python3 setup.py sdist bdist_wheel
python_files = $(shell find find2deny -name "*.py")

sqlite-db=dummy-db.sqlite
ufw-shell-file=block-ip.sh


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

.PHONY: test-release
test-release: clean-all dev-release
	pip uninstall -y find2deny
	pip install --index-url https://test.pypi.org/simple/ --no-deps find2deny
	git commit -a -m "test-release OK at $(date)"

__version__: Makefile
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

.PHONY: clean-all
clean-all: clean
	rm -f $(sqlite-db) $(ufw-shell-file)

.PHONY: run-example
run-example:
	find2deny-cli test-data/rules.cfg

# Auxiliary target run once after clone this project
.PHONY: setup-dist-tool
setup-dist-tool:
	python -m pip install setuptools wheel twine


