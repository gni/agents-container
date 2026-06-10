#!/usr/bin/env bash
set -e

unset GLAB_DEBUG DEBUG GIT_TRACE GIT_TRACE_CURL GIT_TRACE_PACKET GIT_CURL_VERBOSE GITLAB_TOKEN

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

# Security check: Block verbose, debug, and token-dumping arguments
for arg in "$@"; do
    arg_lower="${arg,,}"
    if [[ "$arg_lower" == "-v" || "$arg_lower" == "--verbose" || "$arg_lower" == "--debug" || "$arg_lower" == "-t" || "$arg_lower" == "--show-token" || "$arg_lower" == "--token" ]]; then
        echo "security block: command argument is blocked for security reasons" >&2
        exit 1
    fi
done

# Block commands that can print secrets
if [[ "$COMMAND" == "auth" ]]; then
    if [[ "$SUBCOMMAND" != "status" && "$SUBCOMMAND" != "git-credential" ]]; then
        echo "security block: command is blocked for security reasons" >&2
        exit 1
    fi
fi

if [[ "$COMMAND" == "config" ]]; then
    echo "security block: config command is blocked for security reasons" >&2
    exit 1
fi

ALLOWED_HOSTS="${GITLAB_HOSTS:-gitlab.com}"

is_host_allowed() {
    local host="$1"
    local IFS=','
    for allowed in $ALLOWED_HOSTS; do
        if [[ "$host" == "$allowed" ]]; then
            return 0
        fi
    done
    return 1
}

run_secure_glab() {
    if [ -z "$SECURE_TOKEN" ]; then
        exec /usr/bin/glab-original "$@"
    fi
    
    local TMP_CONF
    TMP_CONF=$(mktemp -d /tmp/glab-conf-XXXXXX)
    trap 'rm -rf "$TMP_CONF"' EXIT INT TERM
    
    local GL_HOST="gitlab.com"
    for ((i=1; i<=$#; i++)); do
        if [[ "${!i}" == "--hostname" ]]; then
            local next_idx=$((i+1))
            GL_HOST="${!next_idx}"
            break
        elif [[ "${!i}" == "-h" ]]; then
            local next_idx=$((i+1))
            GL_HOST="${!next_idx}"
            break
        fi
    done

    set +e
    GLAB_CONFIG_DIR="$TMP_CONF" /usr/bin/glab-original auth login --stdin --hostname "$GL_HOST" <<< "$SECURE_TOKEN" >/dev/null 2>&1
    GLAB_CONFIG_DIR="$TMP_CONF" /usr/bin/glab-original "$@"
    local RET=$?
    set -e
    
    rm -rf "$TMP_CONF"
    trap - EXIT INT TERM
    exit $RET
}

if [[ "$COMMAND" == "auth" && "$SUBCOMMAND" == "git-credential" ]]; then
    CUR_PID=$PPID
    LEGIT_GIT_OP=0
    ROOT_GIT_PID=""
    BLOCKED=0
    
    while [ "$CUR_PID" -gt 1 ]; do
        P_EXE=$(readlink -f /proc/$CUR_PID/exe 2>/dev/null || true)
        P_BASE=$(basename "$P_EXE")
        
        if [[ "$P_EXE" != "/usr/bin/git" && "$P_EXE" != */git-core/git* && "$P_EXE" != "/usr/local/bin/git" && \
              "$P_EXE" != "/usr/bin/bash" && "$P_EXE" != "/bin/bash" && \
              "$P_EXE" != "/usr/bin/sh" && "$P_EXE" != "/bin/sh" && \
              "$P_EXE" != "/usr/bin/dash" && "$P_EXE" != "/bin/dash" && \
              "$P_EXE" != "/usr/bin/zsh" && "$P_EXE" != "/bin/zsh" && \
              "$P_EXE" != "/usr/bin/glab-original" && "$P_EXE" != "/usr/local/bin/vault-wrapper" && \
              "$P_EXE" != "/usr/bin/node" && "$P_EXE" != "/usr/local/bin/node" && \
              "$P_EXE" != "/usr/bin/python3" && "$P_EXE" != "/usr/bin/python" && \
              "$P_EXE" != "/usr/bin/ruby" && "$P_EXE" != "/usr/bin/perl" && \
              "$P_EXE" != "/usr/bin/php" && "$P_EXE" != "/usr/bin/java" && \
              "$P_BASE" != "agy" && "$P_BASE" != "claude" && "$P_BASE" != "codex" && \
              "$P_BASE" != "gemini" && "$P_BASE" != "hermes" && "$P_BASE" != "opencode" && \
              "$P_BASE" != "pi" ]]; then
            echo "security block: malicious executable detected in credential delegation chain: $P_EXE" >&2
            exit 1
        fi
        
        if [[ "$P_EXE" == "/usr/bin/git" || "$P_EXE" == "/usr/local/bin/git" || "$P_EXE" == */git-core/git* ]]; then
            LEGIT_GIT_OP=1
            ROOT_GIT_PID=$CUR_PID
            
            # Check if it is the main git process
            if [[ "$P_EXE" == */git ]]; then
                args=()
                while IFS= read -r -d '' arg; do
                    args+=("$arg")
                done < <(cat "/proc/$CUR_PID/cmdline" 2>/dev/null)
                
                if [ ${#args[@]} -gt 0 ]; then
                    i=1
                    git_cmd=""
                    while [ $i -lt ${#args[@]} ]; do
                        arg="${args[$i]}"
                        if [[ "$arg" == -* ]]; then
                            if [[ "$arg" == "-c" || "$arg" == "-C" ]]; then
                                i=$((i + 2))
                            elif [[ "$arg" == "--git-dir" || "$arg" == "--work-tree" || "$arg" == "--namespace" || "$arg" == "--exec-path" ]]; then
                                i=$((i + 2))
                            else
                                i=$((i + 1))
                            fi
                        else
                            git_cmd="$arg"
                            break
                        fi
                    done
                    
                    if [[ "$git_cmd" == "push" ]]; then
                        if [[ "$ALLOW_PUSH" != "true" ]]; then
                            BLOCKED=1
                        fi
                    fi
                fi
            fi
        fi
        
        NEXT_PID=$(grep -s '^PPid:' "/proc/$CUR_PID/status" | tr -dc '0-9' || echo 0)
        if [ -z "$NEXT_PID" ] || [ "$NEXT_PID" -eq "$CUR_PID" ] || [ "$NEXT_PID" -eq 0 ]; then
            break
        fi
        CUR_PID=$NEXT_PID
    done
    
    if [ $LEGIT_GIT_OP -eq 1 ] && [ $BLOCKED -eq 0 ]; then
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
                    HOST_INPUT=$(echo "$STDIN_PAYLOAD" | grep -E "^host=" | cut -d '=' -f2 | tr -d '\r\n')
                    if [ -z "$HOST_INPUT" ] || ! is_host_allowed "$HOST_INPUT"; then
                        exit 1
                    fi
                fi

                if [ -n "$SECURE_TOKEN" ]; then
                    echo "username=oauth2"
                    echo "password=${SECURE_TOKEN}"
                fi
                exit 0
                
            elif [[ "$arg" == "store" || "$arg" == "erase" ]]; then
                exit 0
            fi
        done
        run_secure_glab "$@"
    fi
    exit 1
fi

run_secure_glab "$@"