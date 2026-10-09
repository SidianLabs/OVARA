set -u
export PATH=$PATH:/usr/local/go/bin
git config --global --add safe.directory '*'
git clone -q /repo /work
(cd /work/proxy && CGO_ENABLED=0 go build -o /usr/local/bin/ovara ./cmd/ovara) || { echo "BUILD FAILED"; exit 1; }
cd /tmp && rm -rf d && ovara init d >/dev/null 2>&1
ovara run -dir d -ui off >/tmp/run.log 2>&1 &
for i in $(seq 1 60); do (echo > /dev/tcp/127.0.0.1/9443) 2>/dev/null && break; sleep 0.5; done

# a hard deny the harness will run into
cat > /tmp/deny.py <<'PY'
import json
p = json.load(open('/tmp/d/policy.json'))
p['rules'].insert(0, {"action_type": "shell", "environment": "*", "resource": "shell:rm -rf*", "deny": True, "description": "no recursive deletes"})
json.dump(p, open('/tmp/d/policy.json', 'w'), indent=2)
PY
python3 /tmp/deny.py; sleep 3

# the harness holds the AGENT token only
AGENT_TOKEN=$(python3 -c "import json;print(json.load(open('/tmp/d/proxy.json'))['gateway_token'])")
python3 -m venv /tmp/v >/dev/null 2>&1
cp -r /repo/sdk/python /tmp/sdkpy && /tmp/v/bin/pip install -q /tmp/sdkpy >/tmp/pip.log 2>&1 || { echo "sdk install failed"; tail -3 /tmp/pip.log; exit 1; }

# the "human": answers the harness's approvals (approve the first, deny the second)
( n=0; while [ $n -lt 2 ]; do
    sleep 1
    ID=$(ovara approvals -dir /tmp/d 2>/dev/null | grep -oE 'apr_[0-9a-f-]+' | head -1)
    [ -z "$ID" ] && continue
    sleep 2
    if [ $n -eq 0 ]; then ovara approve "$ID" -dir /tmp/d >/dev/null 2>&1; else ovara deny "$ID" -dir /tmp/d >/dev/null 2>&1; fi
    n=$((n+1))
  done ) &
HUMAN=$!

/tmp/v/bin/python /repo/tests/agents/harness.py http://127.0.0.1:8080 "$AGENT_TOKEN" 2>&1 | grep -v "^APPROVAL"
# wait for the simulated human only: a bare `wait` would also wait for
# `ovara run`, which never exits, and the container would hang forever.
wait $HUMAN
echo "--- the record"
ovara log -dir /tmp/d 2>&1 | tail -3
echo HARNESS_DONE
