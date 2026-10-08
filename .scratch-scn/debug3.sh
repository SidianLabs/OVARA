set -u
export PATH=$PATH:/usr/local/go/bin
git config --global --add safe.directory '*'
git clone -q --branch hardening/path-to-10 /repo /work
(cd /work/proxy && CGO_ENABLED=0 go build -o /usr/local/bin/ovara ./cmd/ovara) || exit 1
cd /tmp && rm -rf d && ovara init d >/dev/null 2>&1
ovara run -dir d -ui off >/tmp/run.log 2>&1 &
for i in $(seq 1 60); do (echo > /dev/tcp/127.0.0.1/9443) 2>/dev/null && break; sleep 0.5; done
agent() { ( eval "$(ovara env -dir /tmp/d)"; "$@" ); }
code() { agent curl -s -o /dev/null -w '%{http_code}' --max-time 6 "$@"; }

echo "policy file the watcher should be watching:"; grep -E '"policy_file"|"policy_watch|policy_dir' d/config.json
echo "--- before edit"
ovara policy test "GET https://example.com/" -dir /tmp/d 2>&1 | head -3

cat > /tmp/edit.py <<'PY'
import json
p = json.load(open('/tmp/d/policy.json'))
p['rules'].insert(0, {"action_type": "http.request", "environment": "*", "resource": "GET https://example.com/*", "allow": True, "description": "added live"})
json.dump(p, open('/tmp/d/policy.json', 'w'), indent=2)
PY
python3 /tmp/edit.py
for s in 1 3 6; do
  sleep $s
  echo "--- ${s}s later: $(ovara policy test 'GET https://example.com/' -dir /tmp/d 2>&1 | sed -n 2,3p | tr '\n' ' ')"
done
echo "curl: $(code https://example.com/)"
echo "--- gateway log about policy"
grep -iE "polic|reload|watch" /tmp/run.log | tail -10
echo "--- is the edited rule actually valid for the gateway?"
ovara policy -dir /tmp/d 2>&1 | grep -iE "example.com|added live" | head
echo DBG3_DONE
