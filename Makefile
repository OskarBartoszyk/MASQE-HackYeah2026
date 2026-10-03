.PHONY: setup test test-unit test-e2e run build demo clean reset-data

# Use the project virtualenv when `make setup` created it.
PYTHON ?= $(shell [ -x .venv/bin/python ] && echo .venv/bin/python || echo python3)
export GOCACHE := $(CURDIR)/.cache/go-build

# One-time setup on a clean machine: Python deps, dashboard build, Go modules.
setup:
	python3 -m venv .venv
	.venv/bin/python -m pip install -q -r ai-guard/requirements.txt
	cd dashboard && npm ci && npm run build
	go mod download

# Full suite with a PASS/FAIL line per test: Go, Python, demo agent, end-to-end.
test:
	$(PYTHON) scripts/run_tests.py

test-unit:
	$(PYTHON) scripts/run_tests.py --unit

test-e2e:
	$(PYTHON) -m unittest discover -s tests -p 'e2e_test.py' -v

run:
	PYTHON=$(PYTHON) sh scripts/dev.sh

build:
	mkdir -p bin
	cd dashboard && npm run build
	go build -o bin/masqe ./cmd/masqe

demo:
	$(PYTHON) demo-agent/agent.py

clean:
	go clean -testcache

# Start the demo with an empty audit log and budget ledger.
reset-data:
	rm -f data/masqe.db data/masqe.db-wal data/masqe.db-shm
