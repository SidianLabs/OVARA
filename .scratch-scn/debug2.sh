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
pend() { ovara approvals -dir /tmp/d 2>&1 | grep -cE 'apr_'; }

echo "baseline:                 trusted read=$(code https://pypi.org/simple/requests/)  pending=$(pend)"
for n in 1 2 3 4 5; do
  echo "deny #$n (pastebin):       $(code https://pastebin.com/)"
done
echo "after 5 denies:           trusted read=$(code https://pypi.org/simple/requests/)  GET+body=$(code -X GET -d x https://api.github.com/)  pending=$(pend)"
for n in $(seq 1 15); do code https://pastebin.com/ >/dev/null; done
echo "after 20 denies:          trusted read=$(code https://pypi.org/simple/requests/)  GET+body=$(code -X GET -d x https://api.github.com/)  pending=$(pend)"
echo "--- decisions in the receipt log (last 6)"
tail -6 /tmp/d/var/receipts.jsonl | sed -E 's/.*"method":"([A-Z]+)","url":"([^"]+)","decision":"([a-z]+)","status":([0-9]+).*/\1 \2 -> \3 \4/'
echo "--- trust / shield lines in the gateway log"
grep -iE "trust|shield|escalat" /tmp/run.log | tail -8
echo "--- restart: does the effect persist?"
pkill -f "ovara run"; sleep 2
ovara run -dir d -ui off >/tmp/run2.log 2>&1 &
for i in $(seq 1 60); do (echo > /dev/tcp/127.0.0.1/9443) 2>/dev/null && break; sleep 0.5; done
echo "after restart:            trusted read=$(code https://pypi.org/simple/requests/)  pending=$(pend)"
tail -3 /tmp/d/var/receipts.jsonl | sed -E 's/.*"method":"([A-Z]+)","url":"([^"]+)","decision":"([a-z]+)","status":([0-9]+).*/\1 \2 -> \3 \4/'
echo DBG2_DONE
