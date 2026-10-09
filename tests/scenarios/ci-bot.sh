set -u
# Ovara in CI: a background step, an agent with nobody to approve anything,
# and an explicit policy written for the job (docs/use-cases.md, scenario 4).
export PATH=$PATH:/usr/local/go/bin
git config --global --add safe.directory '*'
git clone -q /repo /work
(cd /work/proxy && CGO_ENABLED=0 go build -o /usr/local/bin/ovara ./cmd/ovara) || { echo "BUILD FAILED"; exit 1; }
cd /tmp && rm -rf d && ovara init d >/dev/null 2>&1
TIMEOUT=6
python3 - "$TIMEOUT" <<'PY'
import json, sys
p = json.load(open('/tmp/d/proxy.json')); p['escalate_timeout_sec'] = int(sys.argv[1])
json.dump(p, open('/tmp/d/proxy.json', 'w'), indent=2)
PY

pass=0; fail=0
ok()    { echo "PASS  $1"; pass=$((pass+1)); }
bad()   { echo "FAIL  $1  -- $2"; fail=$((fail+1)); }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "want $2, got $3"; fi; }
code()  { curl -s -o /dev/null -w '%{http_code}' --max-time 40 "$@"; }
# write the job's policy: the default rules plus the given ones, first
setpolicy() {
  python3 - "$@" <<'PY'
import json, sys
p = json.load(open('/tmp/d/policy.default.json'))
extra = [json.loads(a) for a in sys.argv[1:]]
p['rules'] = extra + p['rules']
json.dump(p, open('/tmp/d/policy.json', 'w'), indent=2)
PY
  sleep 3   # hot reload
}
cp /tmp/d/policy.json /tmp/d/policy.default.json

# --- the CI step: start Ovara in the background, wait until it listens ------
ovara run -dir d -ui off >/tmp/run.log 2>&1 &
OVARA=$!
for i in $(seq 1 60); do (echo > /dev/tcp/127.0.0.1/9443) 2>/dev/null && break; sleep 0.5; done
eval "$(ovara env -dir /tmp/d)"

echo "=== A. default policy, nobody to approve"
check "A1 reads from an allowed registry pass" 200 "$(code https://pypi.org/simple/)"
t0=$(date +%s); c=$(code -X POST -d x https://httpbin.org/anything/ci/deploy); t1=$(date +%s)
check "A2 an unapproved write is not let through: it times out (504)" 504 "$c"
el=$((t1 - t0))
[ $el -ge $TIMEOUT ] && [ $el -le $((TIMEOUT + 8)) ] && ok "A3 the job waited about the configured timeout (${el}s for ${TIMEOUT}s)" || bad "A3 wait time" "${el}s for a ${TIMEOUT}s timeout"
check "A4 a read from a host not on the list also waits and times out" 504 "$(code https://example.org/)"
n=$(ovara approvals -dir /tmp/d 2>/dev/null | grep -c 'apr_')
check "A5 timed-out requests leave nothing waiting for a human" 0 "$n"

echo "=== B. an explicit CI policy: allow exactly the expected write"
setpolicy '{"action_type":"http.request","environment":"*","resource":"POST https://httpbin.org/anything/ci/expected","allow":true,"description":"the one write this job makes"}'
check "B1 the expected write goes straight through" 200 "$(code -X POST -d x https://httpbin.org/anything/ci/expected)"
check "B2 a different write to the same host still stops (504)" 504 "$(code -X POST -d x https://httpbin.org/anything/ci/other)"
check "B3 a write to a known dump site is denied at once" 403 "$(code -X POST -d x https://webhook.site/abc)"

echo "=== C. 'allow X, deny every other write' (fail fast instead of waiting)"
setpolicy '{"action_type":"http.request","environment":"*","resource":"POST https://httpbin.org/anything/ci/expected","allow":true,"description":"the one write"}' \
          '{"action_type":"http.request","environment":"*","resource":"POST *","deny":true,"description":"no other writes in CI"}'
t0=$(date +%s); c=$(code -X POST -d x https://httpbin.org/anything/ci/other); t1=$(date +%s)
check "C1 any other write is refused immediately (403)" 403 "$c"
[ $((t1 - t0)) -lt $TIMEOUT ] && ok "C2 without waiting for the timeout ($((t1 - t0))s)" || bad "C2 refusal was not immediate" "$((t1 - t0))s"
# Deny beats allow in the gateway, so a catch-all deny also blocks the write
# the job needs. docs/use-cases.md says so; this keeps the docs honest.
check "C3 a catch-all deny also blocks the allowed write (deny beats allow)" 403 "$(code -X POST -d x https://httpbin.org/anything/ci/expected)"

echo "=== D. the record and the end of the job"
ovara log -dir /tmp/d 2>&1 | grep -q "signed and unbroken" && ok "D1 the receipt chain verifies" || bad "D1 receipt chain" "not verified"
python3 - <<'PY' && ok "D2 every timed-out and refused request is in the receipts" || bad "D2 receipts" "missing entries"
import json, sys
seen = [(r.get('method'), r.get('url', ''), r.get('decision')) for r in map(json.loads, open('/tmp/d/var/receipts.jsonl'))]
want = [('POST', 'ci/deploy'), ('POST', 'ci/other'), ('GET', 'example.org'), ('POST', 'webhook.site')]
sys.exit(0 if all(any(m == w[0] and w[1] in u for m, u, _ in seen) for w in want) else 1)
PY
kill -TERM $OVARA
for i in $(seq 1 20); do kill -0 $OVARA 2>/dev/null || break; sleep 0.5; done
kill -0 $OVARA 2>/dev/null && bad "D3 ovara stops when the job ends" "still running 10s after SIGTERM" || ok "D3 ovara stops when the job ends (SIGTERM)"
ovara log -dir /tmp/d 2>&1 | grep -q "signed and unbroken" && ok "D4 the record still verifies after shutdown" || bad "D4 record after shutdown" "not verified"

echo; echo "RESULT: $pass passed, $fail failed"
