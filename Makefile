# Usage: make test | make lint | make test P=08-detection-rules | make demo | make purple-loop
PYTHON ?= python3
PY_PROJECTS := 01-realtime-ai-siem 02-hitl-soar-bot 04-blast-radius-vuln-scanner 05-sigma-attack-coverage \
               06-alert-clustering-fp-reducer 07-attack-emulator 08-detection-rules 09-evidence-timeline \
               10-ai-analyst-mcp watchfloor/backend
P ?= $(PY_PROJECTS)
DEMO_TMP := $(CURDIR)/.demo-coverage

.PHONY: install test lint pester automation frontend rules evals purple-loop demo lab-check clean

install:
	@for p in $(P); do echo "== $$p"; $(PYTHON) -m pip install -q -r $$p/requirements-dev.txt || exit 1; done

test:
	@for p in $(P); do echo "== $$p"; (cd $$p && $(PYTHON) -m pytest --cov) || exit 1; done
	@if [ "$(P)" = "$(PY_PROJECTS)" ]; then $(MAKE) automation; fi
	@if command -v pwsh >/dev/null 2>&1 && [ "$(P)" = "$(PY_PROJECTS)" ]; then $(MAKE) pester; fi

lint:
	@for p in $(P); do echo "== $$p"; (cd $$p && $(PYTHON) -m ruff check .) || exit 1; done
	@echo "== automation"; cd automation && $(PYTHON) -m ruff check .
	@echo "== watchfloor/tests"; cd watchfloor/tests/backend && $(PYTHON) -m ruff check .

pester:
	cd 03-edr-canary-process-tree && pwsh -NoProfile -Command "Invoke-Pester ./tests -CI"

# n8n playbooks: exports up to date, Code nodes run under node and verified by 02's and 09's real verifiers
automation:
	$(PYTHON) automation/n8n/build_workflows.py --check
	$(PYTHON) -m pytest automation/n8n/tests

frontend:
	cd packages/aegis-ui && npm ci --no-audit --no-fund && npm test
	cd watchfloor/frontend && npm ci --no-audit --no-fund && npm test && npm run typecheck && npm run build:demo

# 08: every rule's samples, then the generated index and SQL
rules:
	cd 08-detection-rules && PYTHONPATH=src $(PYTHON) -m detection_rules build

# 10: the analyst eval suite (triage and prompt-injection cases) with the offline provider
evals:
	cd 10-ai-analyst-mcp && PYTHONPATH=src $(PYTHON) -m ai_analyst eval --out evals/results

# 07 -> hub -> lake -> 08 rules -> findings -> 07 scoring, all in one process
purple-loop:
	cd 07-attack-emulator && $(PYTHON) scripts/purple_loop.py

# Static replay data for the console, from the recorded scenarios and every project's committed output
demo:
	rm -rf $(DEMO_TMP) && mkdir -p $(DEMO_TMP)/05 $(DEMO_TMP)/07
	cp 05-sigma-attack-coverage/examples/output/coverage.json $(DEMO_TMP)/05/
	cp 07-attack-emulator/examples/output/run-*.json $(DEMO_TMP)/07/
	cd watchfloor/backend && \
	  WF_EXPOSURE_FILE=../../04-blast-radius-vuln-scanner/examples/output/findings.json \
	  WF_COVERAGE_DIR=$(DEMO_TMP) \
	  WF_TRIAGE_QUEUE=../../06-alert-clustering-fp-reducer/examples/output/queue.json \
	  WF_RULES_INDEX=../../08-detection-rules/build/rules_index.json \
	  WF_EVIDENCE_DIR=../../09-evidence-timeline/examples/output \
	  WF_ANALYST_DIR=../../10-ai-analyst-mcp/examples/output \
	  PYTHONPATH=src $(PYTHON) -m watchfloor export-demo --out ../frontend/public/demo
	rm -rf $(DEMO_TMP)

lab-check:
	cd lab/ansible && ansible-playbook site.yml --syntax-check

clean:
	find . -type d \( -name __pycache__ -o -name .pytest_cache -o -name .ruff_cache \) -prune -exec rm -rf {} +
	find . -name .coverage -delete
