#!/bin/sh
set -e
# Download the bootstrapper script
curl -fsSL https://antigravity.google/cli/install.sh -o /tmp/installer.sh
# Force the platform to linux_amd64 (statically compiled Go binary runs perfectly under musl/Alpine)
sed -i 's/platform="linux_${arch}_musl"/platform="linux_${arch}"/g' /tmp/installer.sh
# Run the modified bootstrapper
bash /tmp/installer.sh --dir /usr/local/bin
# Clean up
rm -f /tmp/installer.sh

# Crucial Layering Fix: Relocate the binary if it got installed in a home directory
for dir in /root /home/node; do
    if [ -f "$dir/.local/bin/agy" ]; then
        echo "[INSTALLER] Relocating agy from $dir to /usr/local/bin/agy for volume-layer safety..."
        mv "$dir/.local/bin/agy" /usr/local/bin/agy
    fi
done

chmod +x /usr/local/bin/agy 2>/dev/null || true
