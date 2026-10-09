set -u
# `ovara box -profile strict` end to end (milestone 5, docs/box.md §9): real
# npm and pip inside a tier 1 box, a project whose lockfiles pin some
# packages, and a simulated person who answers each approval.
#   - what the lockfiles pin installs without a question
#   - a new dependency pauses once, with its name and version
#   - a refused one never arrives
#   - a package manager pointed at an unlisted registry pauses
#   - npm audit stays free; npm install scripts are off
# Runs as root in a privileged container (tests/box/run.sh strict).
export PATH=$PATH:/usr/local/go/bin
git config --global --add safe.directory '*'
rm -rf /work; git clone -q /repo /work
(cd /work/proxy && CGO_ENABLED=0 go build -o /usr/local/bin/ovara ./cmd/ovara) || { echo "BUILD FAILED"; exit 1; }

pass=0; fail=0
ok()  { echo "PASS  $1"; pass=$((pass+1)); }
bad() { echo "FAIL  $1  -- $2"; fail=$((fail+1)); }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "want $2, got $3"; fi; }

# --- the project: npm and pip lockfiles ------------------------------------------
P=/tmp/sproj; rm -rf $P; mkdir -p $P; cd $P
git init -q -b main; git config user.name dev; git config user.email dev@example.org
cat > package.json <<'J'
{ "name": "sproj", "version": "1.0.0", "private": true, "dependencies": { "left-pad": "1.3.0" } }
J
npm install --package-lock-only --no-fund --no-audit >/dev/null 2>&1 || { echo "could not make the lockfile"; exit 1; }
grep -q '"node_modules/left-pad"' package-lock.json || { echo "lockfile has no left-pad"; exit 1; }
printf 'idna==3.7\n' > requirements.txt
git add -A && git commit -qm init

# --- the agent -------------------------------------------------------------------
cat > /tmp/sagent.sh <<'A'
r() { echo "AGENTRESULT $1 $2"; }
export PIP_CERT="$SSL_CERT_FILE" PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_INPUT=1
r PROFILE "${OVARA_BOX_PROFILE:-unset}"
r SCRIPTS "${npm_config_ignore_scripts:-unset}"
W=$PWD
npm ci --no-fund >/tmp/s-ci.out 2>&1; r LOCKED "exit=$? $( [ -f node_modules/left-pad/package.json ] && echo installed || echo missing)"
mkdir -p /tmp/s1 && cd /tmp/s1 && npm init -y >/dev/null 2>&1
npm install --no-fund --no-audit is-number@7.0.0 >/tmp/s-new.out 2>&1; r NEW "exit=$? $( [ -f node_modules/is-number/package.json ] && echo installed || echo missing)"
npm cache clean --force >/dev/null 2>&1
mkdir -p /tmp/s2 && cd /tmp/s2 && npm init -y >/dev/null 2>&1
npm install --no-fund --no-audit is-number@7.0.0 >/tmp/s-again.out 2>&1; r AGAIN "exit=$? $( [ -f node_modules/is-number/package.json ] && echo installed || echo missing)"
mkdir -p /tmp/s3 && cd /tmp/s3 && npm init -y >/dev/null 2>&1
npm install --no-fund --no-audit kind-of@6.0.3 >/tmp/s-refused.out 2>&1; r REFUSED "exit=$? $( [ -e node_modules/kind-of ] && echo installed || echo absent)"
mkdir -p /tmp/s4 && cd /tmp/s4 && npm init -y >/dev/null 2>&1
npm install --no-fund --no-audit --fetch-retries=0 --registry https://registry.npmmirror.com/ isarray@2.0.5 >/tmp/s-reg.out 2>&1; r OTHERREG "exit=$? $( [ -e node_modules/isarray ] && echo installed || echo absent)"
cd "$W"
python3 -m venv /tmp/sv >/dev/null 2>&1
/tmp/sv/bin/pip install -q -r requirements.txt >/tmp/s-pip1.out 2>&1; r PIPLOCKED "exit=$?"
/tmp/sv/bin/pip install -q six==1.16.0 >/tmp/s-pip2.out 2>&1; r PIPNEW "exit=$? $(/tmp/sv/bin/python -c 'import six;print(six.__version__)' 2>/dev/null)"
npm audit --no-fund >/tmp/s-audit.out 2>&1; r AUDIT "exit=$?"
for f in /tmp/s-*.out; do echo "--- $f"; tail -3 "$f"; done
r DONE yes
A
chmod 755 /tmp/sagent.sh

# --- the person ------------------------------------------------------------------
D=/etc/ovara-strict-dir
: > /tmp/s-human.log; : > /tmp/s-seen.txt
( started=0; while :; do
    sleep 1
    if pgrep -f 'ovara box -dir /etc/ovara-strict' >/dev/null; then started=1; elif [ $started = 1 ]; then break; fi
    ovara approvals -dir $D 2>/dev/null > /tmp/s-approvals.now
    grep -q 'apr_' /tmp/s-approvals.now || continue
    cat /tmp/s-approvals.now >> /tmp/s-seen.txt
    python3 - <<'PY' > /tmp/s-human.cmds
import re
for b in open('/tmp/s-approvals.now').read().split('┌'):
    m = re.search(r'id: (apr_[0-9a-f-]+)', b); raw = re.search(r'raw request:\s+(.*)', b)
    if not m or not raw: continue
    r = raw.group(1).strip()
    if r.startswith('npm:kind-of@') or 'npmmirror' in r: what = 'deny'
    elif r.startswith('npm:') or r.startswith('pypi:'): what = 'approve'
    else: what = 'deny'
    print(what, m.group(1), r)
PY
    while read -r what id raw; do
      [ -n "$id" ] || continue
      echo "$what $id $raw" >> /tmp/s-human.log
      ovara $what "$id" -dir $D >/dev/null 2>&1
    done < /tmp/s-human.cmds
  done ) &
HUMAN=$!

echo "=== the strict box"
timeout 900 ovara box -dir $D -ui off -profile strict -no-commit-back -user ovara-agent $P -- bash /tmp/sagent.sh > /tmp/s-box.out 2>&1
BOX_EXIT=$?
wait $HUMAN
echo "--- ovara box output (tail)"; grep -v '^AGENTRESULT ' /tmp/s-box.out | grep -vE '^(APPROVAL|SKIP) ' | tail -30
echo "--- what the person answered"; cat /tmp/s-human.log
val() { grep -E "^AGENTRESULT $1 " /tmp/s-box.out | head -1 | cut -d' ' -f3- ; }
check "box ran the agent to the end" yes "$(val DONE)"
check "box exit status" 0 "$BOX_EXIT"
grep -qE 'strict installs: [0-9]+ pinned package\(s\) from package-lock.json, requirements.txt' /tmp/s-box.out && ok "box read the project's lockfiles: $(grep -oE '[0-9]+ pinned package\(s\) from [^;]*' /tmp/s-box.out)" || bad "lockfiles not reported" "$(grep 'strict installs' /tmp/s-box.out)"

echo "=== pinned packages"
check "the agent sees the strict profile" strict "$(val PROFILE)"
check "npm install scripts are off" true "$(val SCRIPTS)"
check "npm ci of the locked left-pad needs no one" "exit=0 installed" "$(val LOCKED)"
check "pip install of the pinned idna needs no one" "exit=0" "$(val PIPLOCKED)"
grep -qE 'left-pad|idna' /tmp/s-human.log && bad "a pinned package was asked about" "$(grep -E 'left-pad|idna' /tmp/s-human.log)" || ok "no one was asked about a pinned package"

echo "=== new dependencies"
check "a new npm package arrives after approval" "exit=0 installed" "$(val NEW)"
check "the person was asked once about it, by name and version" 1 "$(grep -c ' npm:is-number@7.0.0$' /tmp/s-human.log)"
check "installing it again later (cache cleared) asks no one" "exit=0 installed" "$(val AGAIN)"
grep -q 'install npm package is-number 7.0.0 (a new dependency' /tmp/s-seen.txt && ok "the approval says what it is: install npm package is-number 7.0.0" || bad "approval wording" "$(grep -m1 -A3 'is-number' /tmp/s-seen.txt)"
grep -q 'asked because: not in the project' /tmp/s-seen.txt && ok "the approval says why it was asked" || bad "approval has no reason" ""
case "$(val REFUSED)" in "exit=0"*) bad "a refused package installed" "$(val REFUSED)";; *" absent") ok "a refused package never arrives ($(val REFUSED))";; *) bad "refused package" "$(val REFUSED)";; esac
grep -q 'deny .* npm:kind-of@6.0.3' /tmp/s-human.log && ok "the refused package was asked about by name and version" || bad "kind-of not asked" ""
case "$(val PIPNEW)" in "exit=0 1.16.0") ok "a new pip package arrives after approval";; *) bad "pip new package" "$(val PIPNEW)";; esac
check "the person was asked once about six" 1 "$(grep -c ' pypi:six@1.16.0$' /tmp/s-human.log)"

echo "=== registries and audit"
case "$(val OTHERREG)" in "exit=0"*) bad "an unlisted registry was used" "$(val OTHERREG)";; *" absent") ok "an unlisted registry pauses and, refused, gives nothing ($(val OTHERREG))";; *) bad "unlisted registry" "$(val OTHERREG)";; esac
grep -q 'deny .*registry.npmmirror.com' /tmp/s-human.log && ok "the person saw the unlisted registry in the approval" || bad "registry pause not seen" ""
grep -qE 'advisories|audits' /tmp/s-human.log && bad "npm audit was asked about" "" || ok "npm audit needed no one"
python3 - <<'PY' && ok "receipts: audit allowed, pinned and approved downloads allowed, the refused one denied" || bad "receipts" "$(tail -5 /tmp/s-receipts.txt)"
import json, sys
rs = [json.loads(l) for l in open('/etc/ovara-strict-dir/var/receipts.jsonl')]
def dec(sub): return [r['decision'] for r in rs if sub in r.get('url','')]
out = open('/tmp/s-receipts.txt','w')
for r in rs: out.write(r['method']+' '+r['url']+' '+r['decision']+'\n')
ok = 'allow' in dec('/-/npm/v1/security/') and 'allow' in dec('left-pad-1.3.0.tgz') \
     and 'allow' in dec('is-number-7.0.0.tgz') and dec('kind-of-6.0.3.tgz') and 'allow' not in dec('kind-of-6.0.3.tgz')
sys.exit(0 if ok else 1)
PY

echo "=== the dev profile (default) asks nothing about packages"
: > /tmp/d-human.log
timeout 300 ovara box -dir $D -ui off -no-commit-back -user ovara-agent $P -- bash -c 'mkdir -p /tmp/d1 && cd /tmp/d1 && npm init -y >/dev/null 2>&1 && npm install --no-fund --no-audit is-odd@3.0.1 >/dev/null 2>&1; echo "AGENTRESULT DEV exit=$? $( [ -f node_modules/is-odd/package.json ] && echo installed || echo missing)"; echo "AGENTRESULT DEVPROFILE $OVARA_BOX_PROFILE"' > /tmp/d-box.out 2>&1
dval() { grep -E "^AGENTRESULT $1 " /tmp/d-box.out | head -1 | cut -d' ' -f3- ; }
check "dev profile: a new package installs without a question" "exit=0 installed" "$(dval DEV)"
check "dev profile is the default" dev "$(dval DEVPROFILE)"

echo; echo "RESULT: $pass passed, $fail failed"
echo "STRICT_DONE"
