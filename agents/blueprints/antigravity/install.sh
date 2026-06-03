#!/bin/sh
# Install dependencies for antigravity agent
curl -fsSL https://antigravity.google/cli/install.sh | bash

# Crucial Layering Fix: Relocate the binary from the home directory (which gets overridden by the runtime volume mount)
# to /usr/local/bin so it remains fully visible and executable at runtime.
if [ -f /home/node/.local/bin/agy ]; then
    echo "[INSTALLER] Relocating agy to /usr/local/bin/agy for volume-layer safety..."
    mv /home/node/.local/bin/agy /usr/local/bin/agy
    chmod +x /usr/local/bin/agy
fi
