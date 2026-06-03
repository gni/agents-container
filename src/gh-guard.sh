#!/usr/bin/env bash
set -e

unset GH_DEBUG DEBUG GIT_TRACE GIT_TRACE_CURL GIT_TRACE_PACKET GIT_CURL_VERBOSE GH_TOKEN GITHUB_TOKEN

SECURE_TOKEN=""
if [ -n "$VAULT_FD" ]; then
    SECURE_TOKEN=$(cat <&${VAULT_FD} 2>/dev/null || true)
    exec {VAULT_FD}<&- 2>/dev/null || true
    unset VAULT_FD
fi

COMMAND=""
SUBCOMMAND=""

for arg in "$@"; do
    if [[ "$arg" != -* ]]; then
        if [ -z "$COMMAND" ]; then
            COMMAND="$arg"
        elif [ -z "$SUBCOMMAND" ]; then
            SUBCOMMAND="$arg"
            break
        fi
    fi
done

COMMAND="${COMMAND,,}"
SUBCOMMAND="${SUBCOMMAND,,}"

run_secure_gh() {
    if [ -z "$SECURE_TOKEN" ]; then
        exec /usr/bin/gh-original "$@"
    fi
    
    local TMP_CONF
    TMP_CONF=$(mktemp -d /tmp/gh-conf-XXXXXX)
    trap 'rm -rf "$TMP_CONF"' EXIT INT TERM
    
    GH_CONFIG_DIR="$TMP_CONF" /usr/bin/gh-original auth login --hostname github.com --with-token <<< "$SECURE_TOKEN" >/dev/null 2>&1
    
    set +e
    GH_CONFIG_DIR="$TMP_CONF" /usr/bin/gh-original "$@"
    local RET=$?
    set -e
    
    rm -rf "$TMP_CONF"
    trap - EXIT INT TERM
    exit $RET
}

if [[ "$COMMAND" == "auth" || "$COMMAND" == "repo" || "$COMMAND" == "secret" || "$COMMAND" == "ssh-key" || "$COMMAND" == "gpg-key" || "$COMMAND" == "config" ]]; then
    
    if [[ "$COMMAND" == "repo" && "$SUBCOMMAND" == "clone" ]]; then
        run_secure_gh "$@"
    fi

    if [[ "$COMMAND" == "auth" && "$SUBCOMMAND" == "status" ]]; then
        run_secure_gh "$@"
    fi

    if [[ "$COMMAND" == "auth" && "$SUBCOMMAND" == "git-credential" ]]; then
        
        CUR_PID=$PPID
        LEGIT_GIT_OP=0
        ROOT_GIT_PID=""
        

        while [ "$CUR_PID" -gt 1 ]; do
            P_EXE=$(readlink -f /proc/$CUR_PID/exe 2>/dev/null || true)
            P_CMD=$(cat /proc/$CUR_PID/cmdline 2>/dev/null | tr '\0' ' ')
            
            P_EXE_BASE=$(basename "$P_EXE" 2>/dev/null || echo "")
            if [[ "$P_EXE" != "/usr/bin/git" && "$P_EXE" != */git-core/git* && "$P_EXE" != "/usr/local/bin/git" && \
                  "$P_EXE" != "/usr/bin/bash" && "$P_EXE" != "/bin/bash" && \
                  "$P_EXE" != "/usr/bin/sh" && "$P_EXE" != "/bin/sh" && \
                  "$P_EXE" != "/usr/bin/dash" && "$P_EXE" != "/bin/dash" && \
                  "$P_EXE" != "/usr/bin/gh-original" && "$P_EXE" != "/usr/local/bin/vault-wrapper" && \
                  "$P_EXE" != "/usr/bin/node" && "$P_EXE" != "/usr/local/bin/node" && \
                  "$P_EXE_BASE" != python* && "$P_EXE_BASE" != ruby* && "$P_EXE_BASE" != perl* && "$P_EXE_BASE" != php* && "$P_EXE_BASE" != java* ]]; then
                echo "[SYSTEM BLOCK] Malicious executable detected in credential delegation chain: $P_EXE" >&2
                exit 1
            fi

            if [[ "$P_EXE" == "/usr/bin/bash" || "$P_EXE" == "/bin/bash" || "$P_EXE" == "/usr/bin/sh" || "$P_EXE" == "/bin/sh" || "$P_EXE" == "/usr/bin/dash" || "$P_EXE" == "/bin/dash" ]]; then
                if [[ "$P_CMD" =~ [\,\<\>\|\&\;\`\$\(\)] ]] || [[ "$P_CMD" == *$'\n'* ]] || [[ "$P_CMD" == *$'\r'* ]]; then
                    echo "[SYSTEM BLOCK] Shell metacharacter injection detected in credential chain" >&2
                    exit 1
                fi
            fi
            
            if [[ "$P_EXE" == "/usr/bin/git" || "$P_EXE" == "/usr/local/bin/git" || "$P_EXE" == */git-core/git* ]]; then
                if [[ "$P_CMD" == *"push"* || "$P_CMD" == *"pull"* || "$P_CMD" == *"fetch"* || "$P_CMD" == *"clone"* || "$P_CMD" == *"ls-remote"* || "$P_CMD" == *"submodule"* || "$P_CMD" == *"remote-https"* ]]; then
                    LEGIT_GIT_OP=1
                    ROOT_GIT_PID=$CUR_PID
                    break
                fi
            fi
            
            NEXT_PID=$(grep -s '^PPid:' "/proc/$CUR_PID/status" | tr -dc '0-9' || echo 0)
            if [ -z "$NEXT_PID" ] || [ "$NEXT_PID" -eq "$CUR_PID" ] || [ "$NEXT_PID" -eq 0 ]; then
                break
            fi
            CUR_PID=$NEXT_PID
        done
        
        if [ $LEGIT_GIT_OP -eq 1 ]; then
            
            if grep -q -E -z 'GIT_TRACE|GIT_CURL_VERBOSE|CORE_TRACEPACKET' "/proc/$ROOT_GIT_PID/environ" 2>/dev/null; then
                exit 1
            fi
            if git config --get-regexp '^(trace2\..*|core\.tracepacket)$' >/dev/null 2>&1; then
                exit 1
            fi
            
            for arg in "$@"; do
                if [[ "$arg" == "get" ]]; then
                    if [ ! -t 0 ]; then
                        STDIN_PAYLOAD=$(cat)
                        if [[ "$STDIN_PAYLOAD" != *"host=github.com"* && "$STDIN_PAYLOAD" != *"host=api.github.com"* ]]; then
                            exit 1
                        fi
                    fi

                    if [ -n "$SECURE_TOKEN" ]; then
                        echo "username=x-access-token"
                        echo "password=${SECURE_TOKEN}"
                    fi
                    exit 0
                    
                elif [[ "$arg" == "store" || "$arg" == "erase" ]]; then
                    exit 0
                fi
            done
            run_secure_gh "$@"
        fi
    fi
    exit 1
fi

run_secure_gh "$@"