#!/usr/bin/env bash
set -e

unset GLAB_DEBUG DEBUG GIT_TRACE GIT_TRACE_CURL GIT_TRACE_PACKET GIT_CURL_VERBOSE GITLAB_TOKEN

SECURE_TOKEN=""
if [ -n "$VAULT_FD" ]; then
    SECURE_TOKEN=$(cat <&${VAULT_FD} 2>/dev/null || true)
    exec {VAULT_FD}<&- 2>/dev/null || true
    unset VAULT_FD
fi

if [ -z "$SECURE_TOKEN" ]; then
    exec /usr/bin/glab-original "$@"
fi

TMP_CONF=$(mktemp -d /tmp/glab-conf-XXXXXX)
trap 'rm -rf "$TMP_CONF"' EXIT INT TERM

GLAB_CONFIG_DIR="$TMP_CONF" /usr/bin/glab-original auth login --stdin --hostname gitlab.com <<< "$SECURE_TOKEN" >/dev/null 2>&1

set +e
GLAB_CONFIG_DIR="$TMP_CONF" /usr/bin/glab-original "$@"
RET=$?
set -e

rm -rf "$TMP_CONF"
trap - EXIT INT TERM
exit $RET