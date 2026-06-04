#!/bin/sh
# Create symlink for volume safety (to satisfy Claude Code's internal paths checks)
mkdir -p /home/node/.local/bin
ln -sf /usr/local/bin/claude /home/node/.local/bin/claude

# Execution logic for claude agent
exec claude "$@"
