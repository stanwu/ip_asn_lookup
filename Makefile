PYTHON ?= python3
HOST ?= 0.0.0.0
PORT ?= 8000
RATE_LIMIT_REQUESTS ?= 60
RATE_LIMIT_WINDOW_SEC ?= 60
TEST_HOST ?= 127.0.0.1
TEST_PORT ?= 18080
TEST_BASE_URL ?= http://$(TEST_HOST):$(TEST_PORT)
TEST_VALID_IP ?= 8.8.8.8
TEST_INVALID_IP ?= 999.999.999.999
LOADTEST_REQUESTS ?= 200
LOADTEST_CONCURRENCY ?= 40
LOADTEST_IP ?= 8.8.8.8
BASE_URL ?= http://127.0.0.1:8000

.PHONY: run test test-unit test-curl loadtest docker-up docker-down

run:
	HOST=$(HOST) \
	PORT=$(PORT) \
	RATE_LIMIT_REQUESTS=$(RATE_LIMIT_REQUESTS) \
	RATE_LIMIT_WINDOW_SEC=$(RATE_LIMIT_WINDOW_SEC) \
	$(PYTHON) -m app.main

test: test-unit test-curl

test-unit:
	$(PYTHON) -m unittest discover -s tests -q

test-curl:
	@set -e; \
	HOST=$(TEST_HOST) PORT=$(TEST_PORT) RATE_LIMIT_REQUESTS=0 $(PYTHON) -m app.main >/tmp/ip_asn_lookup_test_server.log 2>&1 & \
	SERVER_PID=$$!; \
	trap 'kill $$SERVER_PID >/dev/null 2>&1 || true' EXIT INT TERM; \
	for _ in $$(seq 1 50); do \
		curl -fs "$(TEST_BASE_URL)/health" >/dev/null 2>&1 && break; \
		sleep 0.1; \
	done; \
	VALID_CODE=$$(curl -sS -o /dev/null -w "%{http_code}" "$(TEST_BASE_URL)/v1/asn/lookup?ip=$(TEST_VALID_IP)"); \
	INVALID_CODE=$$(curl -sS -o /dev/null -w "%{http_code}" "$(TEST_BASE_URL)/v1/asn/lookup?ip=$(TEST_INVALID_IP)"); \
	echo "valid_ip=$(TEST_VALID_IP) status=$$VALID_CODE"; \
	echo "invalid_ip=$(TEST_INVALID_IP) status=$$INVALID_CODE"; \
	echo "$$VALID_CODE" | grep -Eq "200|502"; \
	echo "$$INVALID_CODE" | grep -Eq "400"

loadtest:
	$(PYTHON) scripts/load_test.py \
		--base-url $(BASE_URL) \
		--ip $(LOADTEST_IP) \
		--requests $(LOADTEST_REQUESTS) \
		--concurrency $(LOADTEST_CONCURRENCY)

docker-up:
	docker compose up --build

docker-down:
	docker compose down
