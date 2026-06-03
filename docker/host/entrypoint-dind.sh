#!/bin/bash
set -e

# Ensure default values are set for internal docker compose evaluation
export AGENT_TYPE="${AGENT_TYPE:-pi}"
export INSTANCE_NAME="${INSTANCE_NAME:-pi_session}"

# Ensure instance directories and dummy files exist to prevent docker compose validation errors
mkdir -p /app/instances/"$INSTANCE_NAME"/.secrets
touch /app/instances/"$INSTANCE_NAME"/.secrets/github_token.txt
touch /app/instances/"$INSTANCE_NAME"/.secrets/gitlab_token.txt
chmod 600 /app/instances/"$INSTANCE_NAME"/.secrets/*.txt

# Fix ownership so files are owned by the host user instead of root
chown -R $(stat -c "%u:%g" /app) /app/instances/"$INSTANCE_NAME"

echo "[dind-entrypoint] Configuring public nameservers for nested DNS resolution..."
echo -e "nameserver 1.1.1.1\nnameserver 8.8.8.8" > /etc/resolv.conf

echo "[dind-entrypoint] Creating gVisor logging directory..."
mkdir -p /var/log/runsc

echo "[dind-entrypoint] Starting nested Docker daemon..."
dockerd-entrypoint.sh &

echo "[dind-entrypoint] Waiting for Docker daemon to initialize..."
timeout=30
while ! docker info >/dev/null 2>&1; do
    timeout=$((timeout - 1))
    if [ "$timeout" -le 0 ]; then
        echo "[dind-entrypoint] ERROR: Docker daemon failed to start within 30 seconds."
        exit 1
    fi
    sleep 1
done
echo "[dind-entrypoint] Docker daemon is up and running!"

echo "[dind-entrypoint] Verifying available Docker runtimes:"
docker info | grep -E "Runtimes|runsc|crun" || true


if [ ! -f /app/config/ottergate/ca.crt ]; then
    echo "[dind-entrypoint] Generating test TLS certificates..."
    mkdir -p /app/config/ottergate/certs
    
    SRV_EXT_FILE=$(mktemp)
    CLI_EXT_FILE=$(mktemp)
    chmod 0600 "$SRV_EXT_FILE" "$CLI_EXT_FILE"
    
    printf "subjectAltName=DNS:ottergate.loop,DNS:*.ottergate.loop,IP:172.20.0.53" > "$SRV_EXT_FILE"
    printf "subjectAltName=DNS:client.test.local" > "$CLI_EXT_FILE"

    openssl req -x509 -new -nodes -keyout /app/config/ottergate/ca.key -sha256 -days 365 -out /app/config/ottergate/ca.crt -subj "/CN=Test CA"
    
    openssl req -new -nodes -keyout /app/config/ottergate/server.key -out /app/config/ottergate/server.csr -subj "/CN=ottergate.loop"
    openssl x509 -req -in /app/config/ottergate/server.csr -CA /app/config/ottergate/ca.crt -CAkey /app/config/ottergate/ca.key -CAcreateserial -out /app/config/ottergate/server.crt -days 365 -sha256 -extfile "$SRV_EXT_FILE"
    
    openssl req -new -nodes -keyout /app/config/ottergate/client.key -out /app/config/ottergate/client.csr -subj "/CN=client.test.local"
    openssl x509 -req -in /app/config/ottergate/client.csr -CA /app/config/ottergate/ca.crt -CAkey /app/config/ottergate/ca.key -CAcreateserial -out /app/config/ottergate/client.crt -days 365 -sha256 -extfile "$CLI_EXT_FILE"

    rm -f "$SRV_EXT_FILE" "$CLI_EXT_FILE"

    # Secure the private keys with correct file permissions
    chmod 600 /app/config/ottergate/ca.key /app/config/ottergate/server.key /app/config/ottergate/client.key 2>/dev/null || true
    chmod 644 /app/config/ottergate/ca.crt /app/config/ottergate/server.crt /app/config/ottergate/client.crt 2>/dev/null || true

    # Fix ownership of config certificates so host user can access them
    chown -R $(stat -c "%u:%g" /app) /app/config/ottergate/ca.key /app/config/ottergate/ca.crt /app/config/ottergate/server.key /app/config/ottergate/server.crt /app/config/ottergate/client.key /app/config/ottergate/client.crt /app/config/ottergate/ca.srl 2>/dev/null || true
fi

if [ ! -f /app/config/ottergate/resolv.conf ]; then
    echo "[dind-entrypoint] Creating resolv.conf pointing to Ottergate (172.20.0.53)..."
    echo "nameserver 172.20.0.53" > /app/config/ottergate/resolv.conf
fi

if ! docker image inspect local/agent-base:latest >/dev/null 2>&1; then
    echo "[dind-entrypoint] Pre-building local/agent-base:latest inside nested Docker..."
    docker build -t local/agent-base:latest -f /app/docker/agent/Dockerfile.base /app
else
    echo "[dind-entrypoint] Found cached local/agent-base:latest, skipping build."
fi

echo "[dind-entrypoint] Starting Ottergate inside nested Docker..."
docker compose -p isolation -f /app/docker/docker-compose.inner.yml up -d ottergate

# Enforce network-level isolation and IP blocklists using iptables
chmod +x /app/src/network/update-iptables.sh
/bin/bash /app/src/network/update-iptables.sh

echo "[dind-entrypoint] System initialized successfully. Streaming Ottergate inner logs:"
touch /var/run/bootstrap_complete

# Continuously stream Ottergate logs even across container restarts/recreations
while true; do
    docker compose -p isolation -f /app/docker/docker-compose.inner.yml logs -f ottergate || true
    sleep 1
done