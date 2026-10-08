set -u
export DEBIAN_FRONTEND=noninteractive
export PATH=$PATH:/usr/local/go/bin
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq sudo iproute2 nftables iptables curl python3 procps >/dev/null 2>&1
git config --global --add safe.directory '*'
git clone -q /repo /work
(cd /work/proxy && CGO_ENABLED=0 go build -o /usr/local/bin/ovara ./cmd/ovara) || { echo "BUILD FAILED"; exit 1; }
cd /tmp && rm -rf d && ovara init d >/dev/null 2>&1

# Start Ovara with a netns boundary (we are root, so no sudo is needed).
ovara run -dir d --boundary netns --boundary-name audit-ns -ui off >/tmp/run.log 2>&1 &
for i in $(seq 1 90); do (echo > /dev/tcp/127.0.0.1/9443) 2>/dev/null && break; sleep 0.5; done
PROXY_IP=$(grep -oE 'HTTPS_PROXY=http://[^ ]*@[0-9.]+:' /tmp/run.log | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
echo "boundary proxy address: ${PROXY_IP:-NOT FOUND}"
[ -n "${PROXY_IP:-}" ] || { echo "could not find the boundary proxy address"; tail -20 /tmp/run.log; exit 1; }

echo
PTOK=$(python3 -c "import json;print(json.load(open('/tmp/d/proxy.json'))['agent_token'])")
PROXY_TOKEN="$PTOK" MODE=netns NS=audit-ns PROXY_IP="$PROXY_IP" PROXY_PORT=9443 GATEWAY_PORT=8080 CA=/tmp/d/var/ca.pem \
  bash /work/tests/redteam/boundary/run.sh
echo "REDTEAM_EXIT=$?"
echo REDTEAM_DONE
