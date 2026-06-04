#!/bin/sh
# Install dependencies for claude agent
curl -fsSL https://claude.ai/install.sh | bash

# Find where the installer placed the claude binary and move it to /usr/local/bin
CLAUDE_PATH=$(find / -name "claude" 2>/dev/null | grep -E "(\.local/bin|/bin/claude|/\.claude/)" | head -n 1)

if [ -n "$CLAUDE_PATH" ]; then
    echo "[INSTALLER] Found claude binary at $CLAUDE_PATH. Relocating to /usr/local/bin/claude..."
    # If it is a symlink, resolve it or copy it
    if [ -L "$CLAUDE_PATH" ]; then
        RESOLVED_PATH=$(readlink -f "$CLAUDE_PATH")
        echo "[INSTALLER] Resolved symlink to $RESOLVED_PATH"
        cp "$RESOLVED_PATH" /usr/local/bin/claude
    else
        mv "$CLAUDE_PATH" /usr/local/bin/claude
    fi
    chmod +x /usr/local/bin/claude
else
    echo "[INSTALLER] Warning: Could not find claude binary in expected locations!"
fi
