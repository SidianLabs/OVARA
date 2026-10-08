set -u
export PATH=$PATH:/usr/local/go/bin
git config --global --add safe.directory '*'
git clone -q /repo /work
(cd /work/proxy && CGO_ENABLED=0 go build -o /usr/local/bin/ovara ./cmd/ovara) || { echo "BUILD FAILED"; exit 1; }

# Two unprivileged users: one runs Ovara, one is the "agent".
useradd -m ovara-op >/dev/null 2>&1
useradd -m agent    >/dev/null 2>&1
install -d -o ovara-op -g ovara-op -m 700 /srv/ovara
as_op()    { runuser -u ovara-op -- "$@"; }
as_agent() { runuser -u agent -- "$@"; }

as_op ovara init /srv/ovara/d >/dev/null 2>&1
chmod 700 /srv/ovara
as_op sh -c 'cd /srv/ovara && nohup ovara run -dir d -ui 127.0.0.1:9090 > run.log 2>&1 &'
for i in $(seq 1 60); do (echo > /dev/tcp/127.0.0.1/9443) 2>/dev/null && break; sleep 0.5; done
OPPID=$(pgrep -u ovara-op -f "ovara run" | head -1)

# The intended hand-off: the operator prints the agent's environment (proxy URL
# with the agent token, CA path) and gives THAT to the agent, nothing else.
as_op ovara env -dir /srv/ovara/d > /tmp/agent.env
cp /srv/ovara/d/var/ca.pem /tmp/ovara-ca.pem 2>/dev/null || as_op cat /srv/ovara/d/var/ca.pem > /tmp/ovara-ca.pem
chmod 644 /tmp/agent.env /tmp/ovara-ca.pem
sed -i 's#/srv/ovara/d/var/ca.pem#/tmp/ovara-ca.pem#g' /tmp/agent.env
# the proxy token the agent legitimately holds
PTOK=$(grep -oE 'agent:[^@]+@' /tmp/agent.env | head -1 | cut -d: -f2 | tr -d '@')

pass=0; fail=0
ok()  { echo "PASS  $1"; pass=$((pass+1)); }
bad() { echo "FAIL  $1  -- $2"; fail=$((fail+1)); }
# an attack succeeded if the command exits 0 (or returns 2xx); we want it to FAIL
blocked() { # name  cmd...
  local name="$1"; shift
  if "$@" >/tmp/atk.out 2>&1; then bad "$name" "attack SUCCEEDED: $(head -c 120 /tmp/atk.out | tr '\n' ' ')"; else ok "$name"; fi
}
code() { curl -s -o /dev/null -w '%{http_code}' --max-time 8 "$@"; }

echo "=== positive control (the agent must still be able to do its job)"
CODE=$(as_agent bash -c ". /tmp/agent.env; curl -s -o /dev/null -w '%{http_code}' --max-time 30 https://pypi.org/simple/requests/")
[ "$CODE" = 200 ] && ok "agent can reach a trusted host through the proxy" || bad "agent cannot use the proxy" "HTTP $CODE"

echo "=== the agent tries to read Ovara's secrets"
blocked "read config.json (operator token)"     as_agent cat /srv/ovara/d/config.json
blocked "read the receipt signing key"          as_agent cat /srv/ovara/d/var/receipt.key
blocked "read the gateway signing key"          as_agent cat /srv/ovara/d/var/gateway.key
blocked "read the proxy CA private key"         as_agent cat /srv/ovara/d/var/ca.key
blocked "list Ovara's directory"                as_agent ls /srv/ovara/d
blocked "read the real API keys from /proc/<ovara>/environ" as_agent cat /proc/$OPPID/environ

echo "=== the agent tries to change its own rules and records"
blocked "edit policy.json to allow everything"  as_agent sh -c 'echo "{}" >> /srv/ovara/d/policy.json'
blocked "append a forged receipt"               as_agent sh -c 'echo "{}" >> /srv/ovara/d/var/receipts.jsonl'
blocked "delete the receipt log"                as_agent rm -f /srv/ovara/d/var/receipts.jsonl
blocked "kill the Ovara process"                as_agent kill -9 "$OPPID"

echo "=== the agent tries to approve its own request over the network"
G=http://127.0.0.1:8080
C1=$(code $G/v1/approval/pending)
[ "$C1" = 401 ] || [ "$C1" = 403 ] && ok "gateway refuses an unauthenticated approvals listing ($C1)" || bad "gateway answered an unauthenticated listing" "HTTP $C1"
C2=$(code -H "Authorization: Bearer $PTOK" $G/v1/approval/pending)
[ "$C2" = 401 ] || [ "$C2" = 403 ] && ok "the proxy token does not open the approvals API ($C2)" || bad "proxy token listed approvals" "HTTP $C2"
C3=$(code -X POST -H "Authorization: Bearer $PTOK" $G/v1/approval/apr_anything/approve)
[ "$C3" = 401 ] || [ "$C3" = 403 ] || [ "$C3" = 404 ] && ok "the proxy token cannot approve ($C3)" || bad "proxy token reached approve" "HTTP $C3"
C4=$(code -H "Authorization: Bearer $PTOK" $G/v1/policy/rules)
[ "$C4" = 401 ] || [ "$C4" = 403 ] || [ "$C4" = 404 ] && ok "the proxy token cannot read or change policy ($C4)" || bad "proxy token reached policy API" "HTTP $C4"
C5=$(code http://127.0.0.1:9090/api/pending)
[ "$C5" = 401 ] && ok "approval page refuses requests without its token" || bad "approval page open without a token" "HTTP $C5"
C6=$(code -x http://127.0.0.1:9443 https://pypi.org/simple/requests/)
[ "$C6" = 407 ] || [ "$C6" = 000 ] && ok "the proxy refuses a client without the proxy token ($C6)" || bad "proxy served an unauthenticated client" "HTTP $C6"

echo "=== after all that, the record is intact"
as_op ovara log -dir /srv/ovara/d 2>&1 | tail -3
as_op ovara log -dir /srv/ovara/d 2>&1 | grep -q "signed and unbroken" && ok "receipt chain still verifies" || bad "receipt chain" "not verified"
kill -0 "$OPPID" 2>/dev/null && ok "Ovara is still running" || bad "Ovara was stopped" ""

echo; echo "RESULT: $pass passed, $fail failed"
echo "ATK_DONE"
