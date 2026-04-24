.PHONY: help install dev-install lint format typecheck test test-cov run docker-build docker-run clean

PYTHON ?= python3
PIP ?= pip

help:
	@echo "DEEPSecurity — developer targets"
	@echo "  install       install runtime deps"
	@echo "  dev-install   install dev + runtime deps + pre-commit"
	@echo "  lint          run ruff"
	@echo "  format        auto-format with ruff"
	@echo "  typecheck     run mypy on deepsecurity/"
	@echo "  test          run pytest"
	@echo "  test-cov      run pytest with coverage report"
	@echo "  run           run Flask dev server"
	@echo "  docker-build  build container image"
	@echo "  docker-run    run container with docker-compose"
	@echo "  clean         remove caches"

install:
	$(PIP) install -r requirements.txt

dev-install:
	$(PIP) install -r requirements-dev.txt
	pre-commit install || true

lint:
	ruff check deepsecurity tests

format:
	ruff format deepsecurity tests
	ruff check --fix deepsecurity tests

typecheck:
	mypy deepsecurity

test:
	pytest -m "not slow"

test-slow:
	pytest -m slow

test-all:
	pytest

test-ops:
	@echo "automating docs/TEST_OPERATIONS.md …"
	pytest -v tests/test_operations_e2e.py

test-cov:
	pytest -m "not slow" --cov=deepsecurity --cov-report=term-missing --cov-report=html

smoke:
	$(PYTHON) scripts/smoke.py

smoke-full:
	$(PYTHON) scripts/smoke.py --full-scan

verify: lint test test-ops smoke
	@echo "all green"

test-loop:
	$(PYTHON) scripts/continuous_tests.py

test-loop-watch:
	$(PYTHON) scripts/continuous_tests.py --watch

test-loop-once:
	$(PYTHON) scripts/continuous_tests.py --once

run:
	FLASK_APP=deepsecurity.api:create_app FLASK_DEBUG=1 flask run --host=$${DEEPSEC_HOST:-127.0.0.1} --port=$${DEEPSEC_PORT:-5000}

docker-build:
	docker build -t deepsecurity:latest -f deploy/Dockerfile .

docker-run:
	docker compose -f deploy/docker-compose.yml up --build

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete 2>/dev/null || true
