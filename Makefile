# Makefile — common development tasks

.PHONY: help run proxy test lint clean bootstrap

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

run: ## Start the web portal
	python3 -m llm_portal

proxy: ## Start the logging reverse proxy
	python3 -m llm_portal proxy

test: ## Run syntax checks and config validation
	@echo "==> Python syntax..."
	python3 -m py_compile llm_portal/__init__.py
	python3 -m py_compile llm_portal/__main__.py
	python3 -m py_compile llm_portal/config.py
	python3 -m py_compile llm_portal/app.py
	python3 -m py_compile llm_portal/proxy.py
	@echo "==> Shell syntax..."
	bash -n userctl.sh
	bash -n scripts/rotate-logs.sh
	bash -n scripts/log-event.sh
	@echo "==> Config validation..."
	python3 -c "import sys; sys.path.insert(0,'.'); from llm_portal.config import load_config; c=load_config('config.example.toml'); assert c.get('portal','port')==8081; print('config OK')"
	@echo "==> Checking for hardcoded paths..."
	@! grep -r '/home/aisrv' llm_portal/ scripts/ *.sh 2>/dev/null | grep -v '.pyc' || (echo "FAIL: hardcoded paths" && exit 1)
	@echo "==> All checks passed ✓"

lint: test ## Alias for test

bootstrap: ## Create the first superadmin (set PORTAL_BOOTSTRAP_PASSWORD)
	@test -n "$$PORTAL_BOOTSTRAP_PASSWORD" || (echo "Set PORTAL_BOOTSTRAP_PASSWORD first" && exit 1)
	python3 -m llm_portal.app createsuperuser admin

smoke: ## Quick smoke test (starts portal, checks response, stops)
	@cp -n config.example.toml config.toml 2>/dev/null || true
	@python3 -m llm_portal & PID=$$!; sleep 3; \
	 curl -sf http://127.0.0.1:8081/portal/login > /dev/null && echo "✓ Portal responds" || echo "✗ Portal not responding"; \
	 kill $$PID 2>/dev/null; true

clean: ## Remove generated files
	rm -rf __pycache__ llm_portal/__pycache__ *.pyc
	rm -rf data/ logs/

install-systemd: ## Install systemd service units (requires sudo)
	@test -d /etc/systemd/system || (echo "systemd not found" && exit 1)
	@for f in systemd/*.service systemd/*.timer; do \
		sed "s|__INSTALL_DIR__|$$(pwd)|g" "$$f" | sudo tee "/etc/systemd/system/$$(basename $$f)" > /dev/null; \
		echo "  installed $$(basename $$f)"; \
	done
	@sudo systemctl daemon-reload
	@echo "✓ Systemd units installed. Enable with: sudo systemctl enable --now llm-portal llm-proxy rotate-logs.timer"
