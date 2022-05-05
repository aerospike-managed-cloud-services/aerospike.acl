#!/usr/bin/env make

SHELL             := /usr/bin/bash
TAGGED_VERSION    := $(shell tools/describe-version)

.PHONY: clean test build cov

build:
	ansible-galaxy collection build --output-path build/
	@ls build/

clean:
	rm -rf build

test:
	pytest  tests/unit/plugins/modules/

cov:
	pytest --cov=./plugins tests/unit/plugins/modules/

format:
	black -l 100 plugins tests
