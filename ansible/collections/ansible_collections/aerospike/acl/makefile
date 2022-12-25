#!/usr/bin/env make

SHELL				:= /usr/bin/env bash
DOCKER				:= docker

.PHONY: clean test build format start-aerospike stop-aerospike print-release-artifact

clean:
	rm -rf build

env: dev-requirements.txt
	test -d env || (python3.10.8 -m venv env; source env/bin/activate; pip install --upgrade pip)
	. env/bin/activate; pip install -qq -r dev-requirements.txt

build: env
	. env/bin/activate; ansible-galaxy collection build --output-path build/

print-release-artifact:
	@echo "build/$$(ls build/)"

test: env
	. env/bin/activate; pytest --cov=./plugins tests/unit/plugins/modules/ --cov-fail-under=88

format: env
	. env/bin/activate; black -l 100 plugins tests

start-aerospike:
	$(DOCKER) run -d --name aerospike -p 3000-3002:3000-3002 -v "$$(pwd)/test_config:/opt/aerospike/etc" aerospike:ee-6.0.0.0 --config-file /opt/aerospike/etc/aerospike.conf

stop-aerospike:
	$(DOCKER) rm --force $$($(DOCKER) ps -a | awk '$$2 ~ /aerospike/ {print $$1}')
