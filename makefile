#!/usr/bin/env make

SHELL				:= /usr/bin/env bash
DOCKER				:= docker

.PHONY: clean test build cov

build:
	ansible-galaxy collection build --output-path build/
	@ls build/

clean:
	rm -rf build

env: dev-requirements.txt
	test -d env || python3.6 -m venv env
	. env/bin/activate; pip install --upgrade pip; pip install -r dev-requirements.txt

test: env
	. env/bin/activate; pytest --cov=./plugins tests/unit/plugins/modules/ --cov-fail-under=88

format:
	black -l 100 plugins tests

start-aerospike:
	$(DOCKER) run -d --name aerospike -p 3000-3002:3000-3002 -v "$$(pwd)/test_config:/opt/aerospike/etc" aerospike:ee-6.0.0.0 --config-file /opt/aerospike/etc/aerospike.conf

stop-aerospike:
	$(DOCKER) rm --force $$($(DOCKER) ps -a | awk '$$2 ~ /aerospike/ {print $$1}')
