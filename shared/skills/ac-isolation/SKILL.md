---
name: agent-ac
description: Workspace location, Python venv setup, and Rust installation guide. Use as a quick reference for environment setup.
---

# Agent Isolation & Setup

## Workspace

Root directory: `/workspace`

## Python Virtual Environment

```bash
# Create
python3 -m venv /workspace/venv

# Activate
source /workspace/venv/bin/activate

# Install a package
pip install <package>

# Deactivate
deactivate
```

## Rust Installation

```bash
# Install via rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Activate in current shell
source "$HOME/.cargo/env"

# Verify
rustc --version && cargo --version
```
