#!/bin/sh
export PATH="/home/node/.opencode/bin:$PATH"
export TMPDIR="/home/node/.tmp"
mkdir -p "$TMPDIR"
exec opencode "$@"