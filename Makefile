# Makefile defines some common tasks which often used during development
#

project_name = find2deny
version = 0.1.12
compile = python3 setup.py sdist bdist_wheel
python_files = $(shell find find2deny -name "*.py")
__version__ = $(project_name)/__version__.py


sqlite-db=dummy-db.sqlite
ufw-shell-file=block-ip.sh


.PHONY: dev-release
dev-release: dev-compile
	python -m twine upload --repository-url https://test.pypi.org/legacy/ dist/*

.PHONY: dev-compile
dev-compile: $(python_files) $(__version__)
	$(compile)

.PHONY:release
release: compile
	python3 -m twine upload dist/*

.PHONY: compile
compile: $(python_files)
	echo $(version) > $(__version__)
	$(compile)

.PHONY: local-install
local-install: venv/bin/find2deny-cli

venv/bin/find2deny-cli: $(python_files) $(__version__)
	echo $(python_files)
	pip install -e .

.PHONY: test-release
test-release: clean-all dev-release
	pip uninstall -y find2deny
	pip install --index-url https://test.pypi.org/simple/ --no-deps $(project_name)
	git commit -a -m 'release OK at `date`'

$(__version__): Makefile
	echo __version__ = \'$(version)-`date "+%s"`\' > $@

.PHONY: unittest
unittest:
	python3 -m pytest

.PHONY: clean-pyc
clean-pyc:
	find . -type f -name "*.py[co]" -delete -or -type d -name "__pycache__" -delete

.PHONY: clean
clean: clean-pyc
	rm -rf .eggs .pytest_cache find2deny.egg-info dist build
	rm -f venv/bin/find2deny-cli

.PHONY: clean-db
clean-db:
	rm -f $(sqlite-db) $(ufw-shell-file)

.PHONY: clean-all
clean-all: clean clean-db


.PHONY: run-example
run-example:
	find2deny-cli test-data/rules.cfg

# Auxiliary target run once after clone this project
.PHONY: setup-dist-tool
setup-dist-tool:
	python -m pip install setuptools wheel twine


