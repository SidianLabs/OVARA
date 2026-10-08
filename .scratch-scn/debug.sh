set -u
export PATH=$PATH:/usr/local/go/bin
git config --global --add safe.directory '*'
git clone -q --branch hardening/path-to-10 /repo /work
(cd /work/proxy && CGO_ENABLED=0 go build -o /usr/local/bin/ovara ./cmd/ovara) || exit 1
cd /tmp && rm -rf d && ovara init d >/dev/null 2>&1
ovara run -dir d -ui off >/tmp/run.log 2>&1 &
for i in $(seq 1 60); do (echo > /dev/tcp/127.0.0.1/9443) 2>/dev/null && break; sleep 0.5; done
agent() { ( eval "$(ovara env -dir /tmp/d)"; "$@" ); }
code() { agent curl -s -o /dev/null -w '%{http_code}' --max-time 8 "$@"; }

echo "--- 1. fresh gateway"
echo "GET+body:       $(code -X GET -d x https://api.github.com/)"
echo "plain trusted:  $(code https://pypi.org/simple/requests/)"
echo "pending now:    $(ovara approvals -dir /tmp/d 2>&1 | grep -cE 'apr_')"

echo "--- 2. after a burst of ordinary traffic (like pip/npm/git)"
for i in $(seq 1 60); do agent curl -s -o /dev/null --max-time 20 https://pypi.org/simple/requests/; done
echo "plain trusted:  $(code https://pypi.org/simple/requests/)"
echo "GET+body:       $(code -X GET -d x https://api.github.com/)"
echo "pending now:    $(ovara approvals -dir /tmp/d 2>&1 | grep -cE 'apr_')"

echo "--- gateway reasons for the last decisions"
grep -iE "escalat|deny|shield|trust|rate|throttle|approval" /tmp/run.log | tail -12
echo "--- policy view of a trusted read"
ovara policy test "GET https://pypi.org/simple/requests/" -dir /tmp/d 2>&1 | tail -6
echo "--- last 6 receipts"
tail -6 /tmp/d/var/receipts.jsonl | cut -c1-220
echo DBG_DONE
