#!/usr/bin/env make

SHELL             := /usr/bin/bash
PROG              := db-user-management
SOURCES           := src/**/*.py test/*.py pyproject.toml poetry.lock pytest.ini tox.ini
TAGGED_VERSION    := $(shell tools/describe-version)
PYPROJECT_VERSION := $(shell poetry version -s)
SDIST             := dist/$(PROG)-$(PYPROJECT_VERSION).tar.gz
WHEEL             := dist/$(PROG)-$(PYPROJECT_VERSION)-py3-none-any.whl

.PHONY: clean test sdist

$(SDIST) $(WHEEL): $(SOURCES)
	@if [[ $(TAGGED_VERSION) != $(PYPROJECT_VERSION) ]]; then \
		echo "** Warning: pyproject.toml version $(PYPROJECT_VERSION) != git tag version $(TAGGED_VERSION)" 1>&2; \
		echo "** The files produced cannot be released" 1>&2; \
	fi
	poetry build

print-release-artifacts: $(SDIST) $(WHEEL)
	@echo $(SDIST) $(WHEEL)

sdist: $(SDIST) $(WHEEL)

clean:
	rm -f $(SDIST) $(WHEEL)

test:
	true

format:
	black src test
	isort src test
