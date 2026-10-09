set -u
# Upgrading a deployment made by an older build. Builds before the restart
# fixes sealed the identity registry twice at the same file_seq and wrote
# approvals as one escalated -> queued journal record, so such a deployment
# refused to start. The current build must refuse it by default (it cannot
# tell it apart from tampering), say how to repair it, repair it once with
# -repair-registry, and then restart normally with the record intact.
export PATH=$PATH:/usr/local/go/bin
git config --global --add safe.directory '*'
git clone -q /repo /work
(cd /work/proxy && CGO_ENABLED=0 go build -o /usr/local/bin/ovara ./cmd/ovara) || { echo "BUILD FAILED"; exit 1; }
# the last build with the bugs: the parent of the commit that fixed them
# (found by subject, so a rewrite of commit ids does not break this)
FIX=$(git -C /work log --format=%H -1 --grep='^fix: deployments restart')
[ -n "$FIX" ] || { echo "BUILD FAILED: fix commit not found"; exit 1; }
git -C /work worktree add -q /old "$FIX^" && (cd /old/proxy && CGO_ENABLED=0 go build -o /usr/local/bin/ovara-old ./cmd/ovara) || { echo "BUILD FAILED (old)"; exit 1; }

pass=0; fail=0
ok()  { echo "PASS  $1"; pass=$((pass+1)); }
bad() { echo "FAIL  $1  -- $2"; fail=$((fail+1)); }
up()  { for i in $(seq 1 60); do (echo > /dev/tcp/127.0.0.1/9443) 2>/dev/null && return 0; kill -0 $1 2>/dev/null || return 1; sleep 0.25; done; return 1; }
stop() { kill -TERM $1; for i in $(seq 1 40); do kill -0 $1 2>/dev/null || break; sleep 0.25; done; kill -9 $1 2>/dev/null; wait $1 2>/dev/null; }

cd /tmp && ovara-old init d >/dev/null 2>&1
python3 -c "import json;p=json.load(open('d/proxy.json'));p['escalate_timeout_sec']=20;json.dump(p,open('d/proxy.json','w'))"

echo "=== an older build runs, a person approves a request"
ovara-old run -dir d -ui off >/tmp/old.log 2>&1 & P=$!
up $P || { echo "FAIL old build did not start"; exit 1; }
( eval "$(ovara-old env -dir /tmp/d)"; curl -s -o /dev/null -w '%{http_code}' --max-time 30 -X POST -d x https://httpbin.org/anything/upgrade > /tmp/post.code ) &
C=$!
for i in $(seq 1 20); do ID=$(ovara-old approvals -dir /tmp/d 2>/dev/null | grep -oE 'apr_[0-9a-f-]+' | head -1); [ -n "$ID" ] && break; sleep 0.5; done
ovara-old approve "$ID" -dir /tmp/d >/dev/null 2>&1
wait $C
[ "$(cat /tmp/post.code)" = 200 ] && ok "old build: the approved request went through" || bad "old build approval" "$(cat /tmp/post.code)"
stop $P

echo "=== the current build on that deployment"
ovara run -dir d -ui off >/tmp/n1.log 2>&1 & P=$!
if up $P; then bad "an affected deployment started without repair" "it should refuse"; stop $P
else
  grep -q "same file_seq with different hash" /tmp/n1.log && ok "refuses the affected deployment by default" || bad "refusal reason" "$(grep 'gateway:' /tmp/n1.log | cut -c1-200)"
  grep -q "repair-registry" /tmp/n1.log && ok "the refusal says how to repair it" || bad "no repair hint" ""
fi
ovara run -dir d -ui off -repair-registry >/tmp/n2.log 2>&1 & P=$!
if up $P; then
  grep -q "identity registry REPAIRED" /tmp/n2.log && ok "-repair-registry repairs it and starts" || bad "repair message" "missing"
  c=$( eval "$(ovara env -dir /tmp/d)"; curl -s -o /dev/null -w '%{http_code}' --max-time 20 https://pypi.org/simple/ )
  [ "$c" = 200 ] && ok "the repaired deployment serves" || bad "repaired deployment" "GET pypi -> $c"
  stop $P
else bad "-repair-registry" "$(grep 'gateway:' /tmp/n2.log | cut -c1-200)"; fi
for n in 1 2; do
  ovara run -dir d -ui off >/tmp/r$n.log 2>&1 & P=$!
  if up $P; then ok "normal restart $n after the repair"; stop $P; else bad "restart $n after the repair" "$(grep 'gateway:' /tmp/r$n.log | cut -c1-200)"; fi
done
ovara run -dir d -ui off -repair-registry >/tmp/r3.log 2>&1 & P=$!
up $P && grep -q "nothing to repair" /tmp/r3.log && ok "-repair-registry on a healthy deployment changes nothing" || bad "-repair-registry on a healthy deployment" "$(tail -2 /tmp/r3.log)"
stop $P
ovara log -dir /tmp/d 2>&1 | grep -q "signed and unbroken" && ok "the old record still verifies" || bad "record" "not verified"

echo; echo "RESULT: $pass passed, $fail failed"
