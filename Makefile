# ---------------------------------------------------------------------------
# Developer shortcuts. Run `make help` for the list of targets.
# ---------------------------------------------------------------------------
VENV ?= .venv
PY   := $(VENV)/bin/python
PIP  := $(VENV)/bin/pip

# Advisories that only affect the end-of-life Python 3.9 development
# interpreter: every fixed release requires Python >= 3.10, so on 3.9 pip
# resolves the last compatible version instead. The CI matrix (3.11 / 3.12),
# the Docker image and production all install the PATCHED releases through the
# environment markers in requirements*.txt, and the pipeline audits with NO
# exceptions at all. See SECURITY.md for the per-CVE reachability analysis.
PY39_EXCEPTIONS := \
	--ignore-vuln PYSEC-2026-2132 \
	--ignore-vuln PYSEC-2026-1845 \
	--ignore-vuln PYSEC-2026-3625 \
	--ignore-vuln PYSEC-2026-1375 \
	--ignore-vuln PYSEC-2026-1374 \
	--ignore-vuln PYSEC-2026-2275 \
	--ignore-vuln PYSEC-2026-142 \
	--ignore-vuln PYSEC-2026-141

LEGACY_PY := $(shell $(PY) -c 'import sys; print("yes" if sys.version_info < (3, 10) else "no")' 2>/dev/null)
ifeq ($(LEGACY_PY),yes)
AUDIT_EXTRA := $(PY39_EXCEPTIONS)
else
AUDIT_EXTRA :=
endif

.DEFAULT_GOAL := help
.PHONY: help venv install run test coverage lint format sast sca audit security \
        smoke workflow-lint clean docker-build docker-run

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sed -e 's/:.*## /|/' \
		| awk -F '|' '{ printf "  %-16s %s\n", $$1, $$2 }'

venv: ## Create the virtual environment
	python3 -m venv $(VENV)
	$(PY) -m pip install --upgrade pip

install: ## Install runtime and development dependencies
	$(PIP) install -r requirements.txt -r requirements-dev.txt

run: ## Start the development server on 127.0.0.1:8000
	$(VENV)/bin/flask --app wsgi run --port 8000

test: ## Run the test suite
	$(VENV)/bin/pytest -q

coverage: ## Run the test suite with the 85% coverage gate
	$(VENV)/bin/pytest -q --cov=app --cov-report=term-missing --cov-fail-under=85

lint: ## Lint and verify formatting
	$(VENV)/bin/ruff check .
	$(VENV)/bin/ruff format --check .

format: ## Auto-format the code
	$(VENV)/bin/ruff check . --fix
	$(VENV)/bin/ruff format .

sast: ## SAST: bandit, fails on medium/high severity findings
	$(VENV)/bin/bandit -c bandit.yaml -r app -ll

sca: ## SCA: pip-audit over the runtime dependencies
	$(VENV)/bin/pip-audit -r requirements.txt $(AUDIT_EXTRA)

audit: ## SCA: pip-audit over runtime AND development dependencies
	$(VENV)/bin/pip-audit -r requirements.txt -r requirements-dev.txt $(AUDIT_EXTRA)

security: sast sca ## Run every security scanner

smoke: ## End-to-end curl scenario against a locally running server
	./docs/curl-examples.sh

workflow-lint: ## Validate the GitHub Actions workflow YAML
	$(PY) -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml')); print('ci.yml is valid YAML')"

docker-build: ## Build the hardened container image
	docker build -t lab1-secure-rest-api:latest .

docker-run: ## Run the container on port 8000
	docker run --rm -p 8000:8000 \
		-e APP_ENV=production \
		-e JWT_SECRET_KEY="$$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')" \
		lab1-secure-rest-api:latest

clean: ## Remove caches and scanner artefacts
	find . -type d -name __pycache__ -not -path "./.venv/*" -exec rm -rf {} +
	rm -rf .pytest_cache .ruff_cache htmlcov coverage.xml .coverage junit.xml
	rm -f bandit-report.json bandit-report.txt bandit.sarif pip-audit.json pip-audit.txt
