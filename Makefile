.DEFAULT_GOAL := help
.PHONY: help dind-start build clean-instance clean-all destroy-all setup-global setup-agent setup-instance run shell

# Dynamically load and export all variables from .env if it exists
-include .env
export

HOST_UID := $(shell id -u)
HOST_GID := $(shell id -g)

RANDOM_ID := $(shell openssl rand -hex 6 2>/dev/null || echo "default")
export GH_SECRET_TARGET_PATH ?= /run/secrets/gh_$(RANDOM_ID)
export GL_SECRET_TARGET_PATH ?= /run/secrets/gl_$(RANDOM_ID)

# Dynamic defaults for agent and instance provisioning
export AGENT_TYPE ?= pi
export INSTANCE_NAME ?= $(AGENT_TYPE)_$(RANDOM_ID)

help:
	@printf "Docker-in-Docker & gVisor Security Mesh Agent Provisioning Control\n"
	@printf "==================================================================\n\n"
	@printf "Commands:\n"
	@printf "  help            Display this documentation.\n"
	@printf "  dind-start      Start the outer Docker-in-Docker host.\n"
	@printf "  setup-global    Initialize core directory structures.\n"
	@printf "  setup-agent     Generate boilerplate install/run scripts for a new AGENT_TYPE.\n"
	@printf "  setup-instance  Provision isolated workspace and cryptographic vaults for INSTANCE_NAME.\n"
	@printf "  run             Execute the agent instance in headless mode behind gVisor in DinD.\n"
	@printf "  shell           Execute the agent instance with an interactive shell behind gVisor in DinD.\n"
	@printf "  clean-instance  Destroy a specific instance and wipe its cryptographic material.\n"
	@printf "  clean-all       Wipe all agent credentials from running instances (retaining workspaces).\n"
	@printf "  destroy-all     Nuclear teardown of all containers, volumes, and ALL workspaces.\n\n"
	@printf "Environment Overrides:\n"
	@printf "  AGENT_TYPE        The agent blueprint to build/run (Default: pi)\n"
	@printf "  INSTANCE_NAME     The unique ID for the container and vault (Default: pi_[RANDOM_ID])\n"
	@printf "  ARGS              Additional arguments to pass to the run command.\n\n"

setup-global:
	@mkdir -p src config docker agents instances
	@if [ ! -f config/.env.example ]; then \
		printf "GITHUB_TOKEN=ghp_your_secure_token_here\nGITLAB_TOKEN=glpat-your_secure_token_here\nGIT_NAME=\"Your Name\"\nGIT_EMAIL=\"your.email@example.com\"\nPARANOID_MODE=true\n" > config/.env.example; \
	fi

setup-agent:
	@mkdir -p agents/$(AGENT_TYPE)
	@if [ ! -f agents/$(AGENT_TYPE)/install.sh ]; then \
		printf "#!/bin/sh\n# Install dependencies for $(AGENT_TYPE)\n" > agents/$(AGENT_TYPE)/install.sh; \
		chmod +x agents/$(AGENT_TYPE)/install.sh; \
	fi
	@if [ ! -f agents/$(AGENT_TYPE)/run.sh ]; then \
		printf "#!/bin/sh\n# Execution logic for $(AGENT_TYPE)\nexec $(AGENT_TYPE) \"\$$@\"\n" > agents/$(AGENT_TYPE)/run.sh; \
		chmod +x agents/$(AGENT_TYPE)/run.sh; \
	fi

setup-instance:
	@mkdir -p instances/$(INSTANCE_NAME)/home instances/$(INSTANCE_NAME)/workspace instances/$(INSTANCE_NAME)/.secrets
	@chmod 700 instances/$(INSTANCE_NAME)/home instances/$(INSTANCE_NAME)/workspace instances/$(INSTANCE_NAME)/.secrets
	@if [ ! -f instances/$(INSTANCE_NAME)/.env ]; then \
		cp config/.env.example instances/$(INSTANCE_NAME)/.env; \
		printf "\n======================================================================\n"; \
		printf " [ACTION REQUIRED] Auto-generated missing .env template.\n"; \
		printf " Please edit: instances/$(INSTANCE_NAME)/.env\n"; \
		printf " Fill in your actual tokens before continuing execution.\n"; \
		printf "======================================================================\n\n"; \
	fi
	@chmod 600 instances/$(INSTANCE_NAME)/.secrets/*.txt 2>/dev/null || true
	@rm -f instances/$(INSTANCE_NAME)/.secrets/*.txt
	@touch instances/$(INSTANCE_NAME)/.secrets/github_token.txt instances/$(INSTANCE_NAME)/.secrets/gitlab_token.txt
	@chmod 600 instances/$(INSTANCE_NAME)/.secrets/*.txt
	@if [ -n "$$GITHUB_TOKEN" ]; then \
		echo "$$GITHUB_TOKEN" > instances/$(INSTANCE_NAME)/.secrets/github_token.txt; \
	elif [ -n "$$GH_TOKEN" ]; then \
		echo "$$GH_TOKEN" > instances/$(INSTANCE_NAME)/.secrets/github_token.txt; \
	elif [ -f instances/$(INSTANCE_NAME)/.env ]; then \
		grep -E "^(GITHUB_TOKEN|GH_TOKEN)=" instances/$(INSTANCE_NAME)/.env | head -n 1 | cut -d '=' -f2- | tr -d '"' | tr -d "'" > instances/$(INSTANCE_NAME)/.secrets/github_token.txt || true; \
	fi
	@if [ -n "$$GITLAB_TOKEN" ]; then \
		echo "$$GITLAB_TOKEN" > instances/$(INSTANCE_NAME)/.secrets/gitlab_token.txt; \
	elif [ -f instances/$(INSTANCE_NAME)/.env ]; then \
		grep -E "^GITLAB_TOKEN=" instances/$(INSTANCE_NAME)/.env | head -n 1 | cut -d '=' -f2- | tr -d '"' | tr -d "'" > instances/$(INSTANCE_NAME)/.secrets/gitlab_token.txt || true; \
	fi
	@chmod 400 instances/$(INSTANCE_NAME)/.secrets/*.txt

dind-start:
	@if ! docker ps --format '{{.Names}}' | grep -q "^isolation-dind-host$$"; then \
		echo "[HOST] Starting outer isolation Docker-in-Docker container..."; \
		docker compose up -d; \
	fi
	@echo "[HOST] Waiting for nested Docker daemon to be fully ready..."
	@until docker exec isolation-dind-host docker info >/dev/null 2>&1; do sleep 1; done
	@echo "[HOST] Waiting for nested Ottergate proxy to be healthy..."
	@until docker exec isolation-dind-host docker inspect -f '{{.State.Health.Status}}' isolation-ottergate-1 2>/dev/null | grep -q "healthy"; do sleep 1; done
	@echo "[HOST] Nested DinD and gVisor isolation mesh are operational!"

run: setup-global setup-agent setup-instance dind-start
	@echo "[RUN] Executing agent $(AGENT_TYPE) (Instance: $(INSTANCE_NAME)) nested behind gVisor..."
	@docker exec -it \
		-e AGENT_TYPE \
		-e INSTANCE_NAME \
		-e GH_SECRET_TARGET_PATH \
		-e GL_SECRET_TARGET_PATH \
		-e GIT_NAME \
		-e GIT_EMAIL \
		-e HOST_UID \
		-e HOST_GID \
		isolation-dind-host \
		docker compose -p isolation -f /app/docker/docker-compose.inner.yml --env-file /app/instances/$(INSTANCE_NAME)/.env run --rm agent $(ARGS)

shell: setup-global setup-agent setup-instance dind-start
	@echo "[SHELL] Launching shell in agent $(AGENT_TYPE) (Instance: $(INSTANCE_NAME)) nested behind gVisor..."
	@docker exec -it \
		-e AGENT_TYPE \
		-e INSTANCE_NAME \
		-e GH_SECRET_TARGET_PATH \
		-e GL_SECRET_TARGET_PATH \
		-e GIT_NAME \
		-e GIT_EMAIL \
		-e HOST_UID \
		-e HOST_GID \
		isolation-dind-host \
		docker compose -p isolation -f /app/docker/docker-compose.inner.yml --env-file /app/instances/$(INSTANCE_NAME)/.env run --entrypoint /bin/sh --rm agent


clean-instance:
	@echo "[CLEAN] Destroying nested agent instance: $(INSTANCE_NAME)"
	@docker exec isolation-dind-host docker rm -f agent_instance_$(INSTANCE_NAME) 2>/dev/null || true
	@rm -rf instances/$(INSTANCE_NAME)/.secrets
clean-all:
	@echo "[CLEAN] Teardown of all nested containers and wiping ALL credentials (retaining workspaces)..."
	@docker exec isolation-dind-host docker compose -p isolation -f /app/docker/docker-compose.inner.yml down -v 2>/dev/null || true
	docker compose down -v 2>/dev/null || true
	rm -rf instances/*/.secrets 2>/dev/null || true
	rm -f instances/*/.env 2>/dev/null || true

destroy-all:
	@echo "[DESTROY] Nuclear teardown of all containers, volumes, and ALL workspaces..."
	@docker exec isolation-dind-host docker compose -p isolation -f /app/docker/docker-compose.inner.yml down -v 2>/dev/null || true
	docker compose down -v 2>/dev/null || true
	rm -rf instances/*
