# BugKit v4 — Install & dev helper
.PHONY: install install-dev test lint clean setup

PYTHON := python3
PIP    := $(PYTHON) -m pip

install:
	$(PIP) install -r requirements.txt --break-system-packages 2>/dev/null || \
	$(PIP) install -r requirements.txt
	@echo "BugKit v4 installed."

install-dev: install
	$(PIP) install pytest pytest-cov --break-system-packages 2>/dev/null || \
	$(PIP) install pytest pytest-cov
	@echo "Dev deps installed."

screenshots:
	$(PYTHON) -m playwright install chromium
	@echo "Chromium installed for screenshots."

test:
	$(PYTHON) -m pytest tests/ -v --tb=short

test-core:
	$(PYTHON) -m pytest tests/test_core.py -v --tb=short

test-modules:
	$(PYTHON) -m pytest tests/test_modules.py -v --tb=short

migrate:
	$(PYTHON) -c "from db.migrations import migrate; from config import settings; migrate(str(settings.db_path))"
	@echo "Database migrated."

lint:
	$(PYTHON) -m py_compile $$(find . -name '*.py' -not -path './__pycache__/*')
	@echo "Syntax OK."

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; true
	find . -name "*.pyc" -delete 2>/dev/null; true
	@echo "Cleaned."

setup: install migrate
	@echo ""
	@echo "BugKit v4 ready. Quick start:"
	@echo "  python main.py target add example.com"
	@echo "  python main.py auth add example.com --name userA --cookie 'session=abc'"
	@echo "  python main.py recon run example.com"
