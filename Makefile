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
	@mkdir -p src/vault src/sandbox src/network config/ottergate config/templates docker agents/blueprints instances
	@if [ ! -f config/templates/.env.example ]; then \
		printf "GITHUB_TOKEN=ghp_your_secure_token_here\nGITLAB_TOKEN=glpat-your_secure_token_here\nGIT_NAME=\"Your Name\"\nGIT_EMAIL=\"your.email@example.com\"\nPARANOID_MODE=true\n" > config/templates/.env.example; \
	fi

setup-agent:
	@mkdir -p agents/blueprints/$(AGENT_TYPE)
	@if [ ! -f agents/blueprints/$(AGENT_TYPE)/install.sh ]; then \
		printf "#!/bin/sh\n# Install dependencies for $(AGENT_TYPE)\n" > agents/blueprints/$(AGENT_TYPE)/install.sh; \
		chmod +x agents/blueprints/$(AGENT_TYPE)/install.sh; \
	fi
	@if [ ! -f agents/blueprints/$(AGENT_TYPE)/run.sh ]; then \
		printf "#!/bin/sh\n# Execution logic for $(AGENT_TYPE)\nexec $(AGENT_TYPE) \"\$$@\"\n" > agents/blueprints/$(AGENT_TYPE)/run.sh; \
		chmod +x agents/blueprints/$(AGENT_TYPE)/run.sh; \
	fi

setup-instance:
	@mkdir -p instances/$(INSTANCE_NAME)/home instances/$(INSTANCE_NAME)/workspace instances/$(INSTANCE_NAME)/.secrets
	@chmod 700 instances/$(INSTANCE_NAME)/home instances/$(INSTANCE_NAME)/workspace instances/$(INSTANCE_NAME)/.secrets
	@if [ ! -f instances/$(INSTANCE_NAME)/.env ]; then \
		cp config/templates/.env.example instances/$(INSTANCE_NAME)/.env; \
		printf "\n* created template environment file: instances/$(INSTANCE_NAME)/.env\n"; \
		printf "  edit this file to configure your credentials before running.\n\n"; \
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
		echo "starting host daemon..."; \
		docker compose up -d; \
	fi
	@echo "waiting for nested docker daemon..."
	@until docker exec isolation-dind-host docker info >/dev/null 2>&1; do sleep 1; done
	@echo "waiting for proxy..."
	@until docker exec isolation-dind-host docker inspect -f '{{.State.Health.Status}}' isolation-ottergate-1 2>/dev/null | grep -q "healthy"; do sleep 1; done
	@echo "mesh network is online."

run: setup-global setup-agent setup-instance dind-start
	@echo "starting agent $(AGENT_TYPE)..."
	@PARANOID=$$(grep -E "^PARANOID_MODE=" instances/$(INSTANCE_NAME)/.env 2>/dev/null | cut -d '=' -f2- | tr -d '"' | tr -d "'" || true); \
	if [ "$$PARANOID" = "true" ] || [ "$$PARANOID_MODE" = "true" ]; then \
		export BASE_IMAGE="local/agent-base:paranoid"; \
		export BASE_IMAGE_TAG="paranoid"; \
	else \
		export BASE_IMAGE="local/agent-base:latest"; \
		export BASE_IMAGE_TAG="latest"; \
	fi; \
	docker exec -it \
		-e AGENT_TYPE \
		-e INSTANCE_NAME \
		-e GH_SECRET_TARGET_PATH \
		-e GL_SECRET_TARGET_PATH \
		-e GIT_NAME \
		-e GIT_EMAIL \
		-e HOST_UID \
		-e HOST_GID \
		-e TERM="$${TERM:-xterm-256color}" \
		-e AGENT_CPUS="$${AGENT_CPUS:-0}" \
		-e AGENT_MEMORY="$${AGENT_MEMORY:-0}" \
		-e BASE_IMAGE="$$BASE_IMAGE" \
		-e BASE_IMAGE_TAG="$$BASE_IMAGE_TAG" \
		isolation-dind-host \
		docker compose -p isolation -f /app/docker/docker-compose.inner.yml --env-file /app/instances/$(INSTANCE_NAME)/.env run --no-deps --rm agent $(ARGS)

shell: setup-global setup-agent setup-instance dind-start
	@echo "starting interactive shell..."
	@PARANOID=$$(grep -E "^PARANOID_MODE=" instances/$(INSTANCE_NAME)/.env 2>/dev/null | cut -d '=' -f2- | tr -d '"' | tr -d "'" || true); \
	if [ "$$PARANOID" = "true" ] || [ "$$PARANOID_MODE" = "true" ]; then \
		export BASE_IMAGE="local/agent-base:paranoid"; \
		export BASE_IMAGE_TAG="paranoid"; \
	else \
		export BASE_IMAGE="local/agent-base:latest"; \
		export BASE_IMAGE_TAG="latest"; \
	fi; \
	docker exec -it \
		-e AGENT_TYPE \
		-e INSTANCE_NAME \
		-e GH_SECRET_TARGET_PATH \
		-e GL_SECRET_TARGET_PATH \
		-e GIT_NAME \
		-e GIT_EMAIL \
		-e HOST_UID \
		-e HOST_GID \
		-e TERM="$${TERM:-xterm-256color}" \
		-e AGENT_CPUS="$${AGENT_CPUS:-0}" \
		-e AGENT_MEMORY="$${AGENT_MEMORY:-0}" \
		-e BASE_IMAGE="$$BASE_IMAGE" \
		-e BASE_IMAGE_TAG="$$BASE_IMAGE_TAG" \
		isolation-dind-host \
		docker compose -p isolation -f /app/docker/docker-compose.inner.yml --env-file /app/instances/$(INSTANCE_NAME)/.env run --no-deps --entrypoint /bin/sh --rm agent


clean-instance:
	@echo "cleaning credentials for $(INSTANCE_NAME)..."
	@docker exec isolation-dind-host docker rm -f agent_instance_$(INSTANCE_NAME) 2>/dev/null || true
	@rm -rf instances/$(INSTANCE_NAME)/.secrets
clean-all:
	@echo "cleaning all credentials..."
	@docker exec isolation-dind-host docker compose -p isolation -f /app/docker/docker-compose.inner.yml down -v 2>/dev/null || true
	docker compose down -v 2>/dev/null || true
	rm -rf instances/*/.secrets 2>/dev/null || true
	rm -f instances/*/.env 2>/dev/null || true

destroy-all:
	@echo "destroying all workspaces and containers..."
	@docker exec isolation-dind-host docker compose -p isolation -f /app/docker/docker-compose.inner.yml down -v 2>/dev/null || true
	docker compose down -v 2>/dev/null || true
	rm -rf instances/*
