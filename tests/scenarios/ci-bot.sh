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
check "A2 an unapproved write is not let through: held, then told to retry (503)" 503 "$c"
el=$((t1 - t0))
[ $el -ge $TIMEOUT ] && [ $el -le $((TIMEOUT + 8)) ] && ok "A3 the job waited about the configured timeout (${el}s for ${TIMEOUT}s)" || bad "A3 wait time" "${el}s for a ${TIMEOUT}s timeout"
check "A4 a read from a host not on the list also waits, then is told to retry (503)" 503 "$(code https://example.org/)"
n=$(ovara approvals -dir /tmp/d 2>/dev/null | grep -c 'apr_')
check "A5 the held requests stay open for a person (approving one makes the job's retry run)" 2 "$n"

echo "=== B. an explicit CI policy: allow exactly the expected write"
setpolicy '{"action_type":"http.request","environment":"*","resource":"POST https://httpbin.org/anything/ci/expected","allow":true,"description":"the one write this job makes"}'
check "B1 the expected write goes straight through" 200 "$(code -X POST -d x https://httpbin.org/anything/ci/expected)"
check "B2 a different write to the same host still stops (503, told to retry)" 503 "$(code -X POST -d x https://httpbin.org/anything/ci/other)"
check "B3 a write to a known dump site is denied at once" 403 "$(code -X POST -d x https://webhook.site/abc)"

echo "=== P. policy profiles (ovara policy profile)"
ovara policy profile balanced -dir /tmp/d >/dev/null 2>&1; sleep 3
check "P1 balanced: a read from an unlisted host goes through" 200 "$(code https://example.org/)"
check "P2 balanced: a write still waits for a person (503)" 503 "$(code -X POST -d x https://httpbin.org/anything/ci/profile)"
check "P3 balanced: a known dump site is still refused" 403 "$(code https://pastebin.com/)"
ovara policy profile observe -dir /tmp/d >/dev/null 2>&1; sleep 3
check "P4 observe: a write is refused at once, not held (403)" 403 "$(code -X POST -d x https://httpbin.org/anything/ci/profile)"
n=$(ovara policy suggest -dir /tmp/d 2>/dev/null | grep -c '"resource"')
[ "$n" -ge 3 ] && ok "P5 ovara policy suggest proposes rules from the receipts ($n)" || bad "P5 policy suggest" "$n rule(s)"
ovara policy profile strict -dir /tmp/d >/dev/null 2>&1; sleep 3
check "P6 strict again: the unlisted read waits for a person (503)" 503 "$(code https://example.org/)"

echo "=== C. 'allow X, deny every other write' (fail fast instead of waiting)"
setpolicy '{"action_type":"http.request","environment":"*","resource":"POST https://httpbin.org/anything/ci/expected","allow":true,"description":"the one write"}' \
          '{"action_type":"http.request","environment":"*","resource":"POST *","deny":true,"description":"no other writes in CI"}'
t0=$(date +%s); c=$(code -X POST -d x https://httpbin.org/anything/ci/other); t1=$(date +%s)
check "C1 any other write is refused immediately (403)" 403 "$c"
[ $((t1 - t0)) -lt $TIMEOUT ] && ok "C2 without waiting for the timeout ($((t1 - t0))s)" || bad "C2 refusal was not immediate" "$((t1 - t0))s"
# The exact allow is more specific than the catch-all deny, so the one write
# the job needs still passes (precedence most-specific, written by ovara init).
check "C3 the allowed write still passes under the catch-all deny (most specific rule decides)" 200 "$(code -X POST -d x https://httpbin.org/anything/ci/expected)"
# ...and an older policy file without the precedence field keeps the old rule
python3 - <<'PY'
import json
p = json.load(open('/tmp/d/policy.json')); p.pop('precedence', None)
json.dump(p, open('/tmp/d/policy.json', 'w'), indent=2)
PY
sleep 3
check "C4 without the precedence field a catch-all deny wins (older files unchanged)" 403 "$(code -X POST -d x https://httpbin.org/anything/ci/expected)"

echo "=== E. an organisation's baseline the job's policy may only narrow"
setpolicy '{"action_type":"http.request","environment":"*","resource":"POST https://httpbin.org/anything/ci/expected","allow":true,"description":"the one write"}'
cat > /tmp/d/baseline.json <<'JSON'
{"version":"org","precedence":"most-specific","rules":[
 {"action_type":"http.request","environment":"*","resource":"POST https://httpbin.org/anything/ci/expected","deny":true,"description":"the organisation forbids this endpoint"}]}
JSON
ovara policy baseline keygen -out /tmp/k >/dev/null && ovara policy baseline sign -key /tmp/k/baseline.key -in /tmp/d/baseline.json >/dev/null \
  && ok "E1 the baseline is signed (ovara policy baseline keygen, sign)" || bad "E1 baseline signing" "keygen or sign failed"
python3 - <<'PY'
import json
c = json.load(open('/tmp/d/config.json'))
c['policy_baseline_file'] = 'baseline.json'; c['policy_baseline_pubkey'] = open('/tmp/k/baseline.pub').read().strip()
json.dump(c, open('/tmp/d/config.json', 'w'), indent=2)
PY
stop()  { kill -TERM $OVARA; for i in $(seq 1 20); do kill -0 $OVARA 2>/dev/null || break; sleep 0.5; done; }
start() { ovara run -dir d -ui off >>/tmp/run.log 2>&1 & OVARA=$!; for i in $(seq 1 60); do (echo > /dev/tcp/127.0.0.1/9443) 2>/dev/null && break; sleep 0.5; done; }
stop; start   # the baseline is read at start
check "E2 the write the job's policy allows is refused by the organisation (403)" 403 "$(code -X POST -d x https://httpbin.org/anything/ci/expected)"
curl -s --max-time 40 -X POST -d x https://httpbin.org/anything/ci/expected 2>/dev/null | grep -q "org baseline" && ok "E3 the refusal names the org baseline" || bad "E3 refusal text" "does not say org baseline"
check "E4 what the baseline does not mention still follows the job's policy" 200 "$(code https://pypi.org/simple/)"
ovara doctor -dir /tmp/d 2>&1 | grep -q "policy baseline.*verifies" && ok "E5 ovara doctor: the baseline's signature verifies" || bad "E5 doctor" "no verified-baseline line"
# a baseline loosened by someone without the key does not load
stop; sed -i 's/"deny":true/"allow":true/' /tmp/d/baseline.json
timeout 30 ovara run -dir d -ui off >/tmp/run2.log 2>&1; rc=$?
[ $rc -ne 0 ] && grep -q "does not verify" /tmp/run2.log && ok "E6 a loosened, unsigned baseline stops the gateway instead of being skipped" || bad "E6 tampered baseline" "exit $rc: $(tail -1 /tmp/run2.log)"
sed -i 's/"allow":true/"deny":true/' /tmp/d/baseline.json; start

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
ovara attest verify -dir /tmp/d >/tmp/attest.out 2>&1 && ok "D5 the run's attestation verifies offline ($(grep -c . /tmp/attest.out) lines)" || bad "D5 attestation" "$(tail -3 /tmp/attest.out)"
ovara incident bundle -dir /tmp/d -out /tmp/case.tar.gz >/dev/null 2>&1; mkdir -p /tmp/case && tar -xzf /tmp/case.tar.gz -C /tmp/case
A=$(ls /tmp/case/ovara-incident/attestations/*.intoto.json 2>/dev/null | tail -1)
[ -n "$A" ] && (cd /tmp/case/ovara-incident && ovara attest verify "$A" -receipts receipts.jsonl -pubkey receipt_pubkey.hex -segment segment.json >/tmp/attest2.out 2>&1) && ok "D6 the same statement verifies from the incident bundle alone" || bad "D6 attestation from the bundle" "$(tail -3 /tmp/attest2.out 2>/dev/null)"

echo; echo "RESULT: $pass passed, $fail failed"
