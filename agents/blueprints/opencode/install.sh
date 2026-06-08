#!/bin/sh
npm install -g opencode-ai
export TMPDIR="/home/node/.tmp"
mkdir -p "$TMPDIR"
mkdir -p /home/node/.local/bin
ln -sf /home/node/.opencode/bin/opencode /home/node/.local/bin/opencode