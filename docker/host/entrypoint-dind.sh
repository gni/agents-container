#!/bin/bash
set -e

# Ensure default values are set for internal docker compose evaluation
export AGENT_TYPE="${AGENT_TYPE:-pi}"
export INSTANCE_NAME="${INSTANCE_NAME:-pi_session}"

# Ensure instance directories and dummy files exist to prevent docker compose validation errors
INSTANCES_DIR="${INSTANCES_DIR:-instances}"
mkdir -p /app/"$INSTANCES_DIR"/"$INSTANCE_NAME"/.secrets
touch /app/"$INSTANCES_DIR"/"$INSTANCE_NAME"/.secrets/github_token.txt
touch /app/"$INSTANCES_DIR"/"$INSTANCE_NAME"/.secrets/gitlab_token.txt
chmod 600 /app/"$INSTANCES_DIR"/"$INSTANCE_NAME"/.secrets/*.txt

# Fix ownership so files are owned by the host user instead of root
chown -R $(stat -c "%u:%g" /app) /app/"$INSTANCES_DIR"/"$INSTANCE_NAME"

echo "dind: configuring public nameservers..."
echo -e "nameserver 1.1.1.1\nnameserver 8.8.8.8" > /etc/resolv.conf

echo "dind: creating gvisor logging directory..."
mkdir -p /var/log/runsc /var/log/gvisor

if [ "$GVISOR_DEBUG" = "true" ]; then
    echo "dind: enabling gVisor debug and strace logs..."
    cat <<EOF > /etc/docker/daemon.json
{
  "log-level": "warn",
  "runtimes": {
    "runsc": {
      "path": "/usr/local/bin/runsc",
      "runtimeArgs": [
        "--platform=ptrace",
        "--debug",
        "--strace",
        "--strace-syscalls=execve,connect,socket,clone,ptrace",
        "--debug-log=/var/log/gvisor/%ID%/runsc.log.%%COMMAND%%"
      ]
    },
    "crun": {
      "path": "/usr/bin/crun"
    }
  }
}
EOF
else
    echo "dind: gVisor debug logs are disabled."
    cat <<EOF > /etc/docker/daemon.json
{
  "log-level": "warn",
  "runtimes": {
    "runsc": {
      "path": "/usr/local/bin/runsc",
      "runtimeArgs": [
        "--platform=ptrace"
      ]
    },
    "crun": {
      "path": "/usr/bin/crun"
    }
  }
}
EOF
fi

echo "dind: starting nested docker daemon..."
dockerd-entrypoint.sh &

echo "dind: waiting for docker daemon..."
timeout=30
while ! docker info >/dev/null 2>&1; do
    timeout=$((timeout - 1))
    if [ "$timeout" -le 0 ]; then
        echo "dind: error: docker daemon failed to start within 30 seconds"
        exit 1
    fi
    sleep 1
done
echo "dind: docker daemon is up and running."

echo "dind: runtimes:"
docker info | grep -E "Runtimes|runsc|crun" || true


if [ ! -f /app/config/ottergate/certs/ca.crt ]; then
    echo "dind: generating tls certificates..."
    mkdir -p /app/config/ottergate/certs/server /app/config/ottergate/certs/client /app/config/ottergate/certs/custom
    
    SRV_EXT_FILE=$(mktemp)
    CLI_EXT_FILE=$(mktemp)
    chmod 0600 "$SRV_EXT_FILE" "$CLI_EXT_FILE"
    
    printf "subjectAltName=DNS:ottergate.loop,DNS:*.ottergate.loop,IP:172.20.0.53" > "$SRV_EXT_FILE"
    printf "subjectAltName=DNS:client.test.local" > "$CLI_EXT_FILE"

    openssl req -x509 -new -nodes -keyout /app/config/ottergate/certs/ca.key -sha256 -days 365 -out /app/config/ottergate/certs/ca.crt -subj "/CN=Test CA"
    
    openssl req -new -nodes -keyout /app/config/ottergate/certs/server/server.key -out /app/config/ottergate/certs/server/server.csr -subj "/CN=ottergate.loop"
    openssl x509 -req -in /app/config/ottergate/certs/server/server.csr -CA /app/config/ottergate/certs/ca.crt -CAkey /app/config/ottergate/certs/ca.key -CAcreateserial -out /app/config/ottergate/certs/server/server.crt -days 365 -sha256 -extfile "$SRV_EXT_FILE"
    
    openssl req -new -nodes -keyout /app/config/ottergate/certs/client/client.key -out /app/config/ottergate/certs/client/client.csr -subj "/CN=client.test.local"
    openssl x509 -req -in /app/config/ottergate/certs/client/client.csr -CA /app/config/ottergate/certs/ca.crt -CAkey /app/config/ottergate/certs/ca.key -CAcreateserial -out /app/config/ottergate/certs/client/client.crt -days 365 -sha256 -extfile "$CLI_EXT_FILE"

    rm -f "$SRV_EXT_FILE" "$CLI_EXT_FILE"

    # Secure the private keys with correct file permissions
    chmod 600 /app/config/ottergate/certs/ca.key /app/config/ottergate/certs/server/server.key /app/config/ottergate/certs/client/client.key 2>/dev/null || true
    chmod 644 /app/config/ottergate/certs/ca.crt /app/config/ottergate/certs/server/server.crt /app/config/ottergate/certs/client/client.crt 2>/dev/null || true

    # Fix ownership of config certificates so host user can access them
    chown -R $(stat -c "%u:%g" /app) /app/config/ottergate/certs 2>/dev/null || true
fi

# Ensure the Ottergate CA certificate is available in custom certs for the agent to trust it
cp /app/config/ottergate/certs/ca.crt /app/config/ottergate/certs/custom/ottergate-ca.crt 2>/dev/null || true
chmod 644 /app/config/ottergate/certs/custom/ottergate-ca.crt 2>/dev/null || true
chown $(stat -c "%u:%g" /app) /app/config/ottergate/certs/custom/ottergate-ca.crt 2>/dev/null || true


if [ ! -f /app/config/ottergate/resolv.conf ]; then
    echo "dind: creating resolv.conf..."
    echo "nameserver 172.20.0.53" > /app/config/ottergate/resolv.conf
fi

if ! docker image inspect local/agent-base:latest >/dev/null 2>&1; then
    echo "dind: pre-building base image (local/agent-base)..."
    docker build -t local/agent-base:latest -f /app/docker/agent/Dockerfile.base /app
else
    echo "dind: using cached base image."
fi

if ! docker image inspect local/agent-base:paranoid >/dev/null 2>&1; then
    echo "dind: pre-building paranoid base image (local/agent-base:paranoid)..."
    docker build -t local/agent-base:paranoid -f /app/docker/agent/Dockerfile.paranoid /app
else
    echo "dind: using cached paranoid base image."
fi

echo "dind: starting ottergate proxy..."
docker compose -p isolation -f /app/docker/docker-compose.inner.yml up -d ottergate

# Enforce network-level isolation and IP blocklists using iptables
chmod +x /app/src/network/update-iptables.sh
/bin/bash /app/src/network/update-iptables.sh

echo "dind: initialization complete."
touch /var/run/bootstrap_complete

# Keep the entrypoint script alive without streaming proxy logs to host logs
exec tail -f /dev/null