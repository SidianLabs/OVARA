#!/usr/bin/env bash
# Milestone 7, the real-key soak: the agents, against the real model APIs,
# each in a tier 2 box with the ci profile (nobody answers), round after
# round for SOAK_MINUTES, all writing to one Ovara deployment so the receipt
# chain grows the way a long working day grows it.
#
# Each round copies tests/soak/fixture (a module with one planted bug) into
# a fresh repository and asks the agent to make its tests pass. Whether the
# model fixes the bug is reported, not required: that is the model's job.
# What must hold, every round, is Ovara's job:
#   - the agent reached its model API through Ovara (a 2xx from it);
#   - the real key appears nowhere the agent could write: not in its output,
#     not in its workspace;
#   - the agent did not edit the tests;
# and at the end the whole receipt chain verifies.
#
# It changes this machine (like tests/box/host.sh): run it on a disposable
# one and say so with OVARA_TEST_ON_HOST=1.
#
#   OVARA_TEST_ON_HOST=1 ANTHROPIC_API_KEY=... OPENAI_API_KEY=... tests/soak/soak.sh
#
# SOAK_MINUTES   how long to keep starting rounds (default 60)
# SOAK_AGENTS    which agents (default: every one a key is set for)
# SOAK_REPORT    where to write the markdown report (default /tmp/soak-report.md)
# SOAK_*_MODEL   model for claude, codex, opencode or aider (optional)
# SKIP_IMAGE_BUILD=1 uses ovara-box and ovara-box-<agent> as they are
set -uo pipefail
[ "${OVARA_TEST_ON_HOST:-}" = 1 ] || { echo "the soak changes this machine; run it on a disposable one with OVARA_TEST_ON_HOST=1" >&2; exit 2; }
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
SUDO=""; [ "$(id -u)" = 0 ] || SUDO="sudo"
minutes="${SOAK_MINUTES:-60}"
report="${SOAK_REPORT:-/tmp/soak-report.md}"
work=/tmp/soak; d=$work/d

anth="${ANTHROPIC_API_KEY:-}"; oai="${OPENAI_API_KEY:-}"
if [ -z "${SOAK_AGENTS:-}" ]; then
  SOAK_AGENTS=""
  [ -n "$anth" ] && SOAK_AGENTS="claude"
  [ -n "$oai" ] && SOAK_AGENTS="$SOAK_AGENTS codex aider"
  [ -n "$anth$oai" ] && SOAK_AGENTS="$SOAK_AGENTS opencode"
fi
read -r -a agents <<< "$SOAK_AGENTS"
[ "${#agents[@]}" -gt 0 ] || { echo "no API keys set (ANTHROPIC_API_KEY, OPENAI_API_KEY): nothing to soak" >&2; exit 2; }

echo "=== building ovara and the images (${agents[*]})"
(cd "$repo/proxy" && CGO_ENABLED=0 go build -o /tmp/ovara-soak-bin ./cmd/ovara) || exit 1
$SUDO install -m 0755 /tmp/ovara-soak-bin /usr/local/bin/ovara
if [ "${SKIP_IMAGE_BUILD:-}" != 1 ]; then
  docker build -q -t ovara-box "$repo/box" >/dev/null || exit 1
  for a in "${agents[@]}"; do
    docker build -q --build-arg AGENT="$a" -t "ovara-box-$a" "$repo/box/agents" >/dev/null || exit 1
  done
fi

# ovara box needs root; keep the keys (and PATH) across sudo
ovcmd=(ovara)
[ -z "$SUDO" ] || ovcmd=("$SUDO" --preserve-env=ANTHROPIC_API_KEY,OPENAI_API_KEY env "PATH=$PATH" ovara)
ov() { "${ovcmd[@]}" "$@"; }
# another Ovara on this machine would take the box's ports and every round
# would fail for a reason that has nothing to do with the agents
for port in 9443 8080; do
  if (echo > "/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    echo "port $port is in use (another ovara run or box?): stop it first" >&2; exit 2
  fi
done
$SUDO rm -rf "$work"; mkdir -p "$work"
ov init "$d" >/dev/null || exit 1

prompt='The tests in this directory fail. Fix calc.py so that `python3 -m unittest` passes. Do not change test_calc.py.'
# the command each agent runs in the box; keys there are Ovara's placeholders
agent_cmd() {
  case "$1" in
    claude)
      echo "export DISABLE_AUTOUPDATER=1 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1; \
timeout 900 claude -p '$prompt' --permission-mode bypassPermissions --max-turns 30 ${SOAK_CLAUDE_MODEL:+--model $SOAK_CLAUDE_MODEL}" ;;
    codex)
      echo "printenv OPENAI_API_KEY | codex login --with-api-key >/dev/null 2>&1; \
timeout 900 codex exec --skip-git-repo-check --dangerously-bypass-approvals-and-sandbox ${SOAK_CODEX_MODEL:+-m $SOAK_CODEX_MODEL} '$prompt'" ;;
    opencode)
      local m="${SOAK_OPENCODE_MODEL:-}"
      [ -n "$m" ] || { if [ -n "$anth" ]; then m=anthropic/claude-sonnet-4-5; else m=openai/gpt-4.1-mini; fi; }
      echo "timeout 900 opencode run -m $m '$prompt'" ;;
    aider)
      echo "export LITELLM_LOCAL_MODEL_COST_MAP=True; yes y | timeout 900 aider --model ${SOAK_AIDER_MODEL:-gpt-4.1-mini} \
--message '$prompt' --yes-always --no-pretty --no-stream --no-check-update --no-show-model-warnings --no-analytics \
--no-auto-commits --no-git --map-tokens 0 --chat-history-file /tmp/aider.chat.md --input-history-file /tmp/aider.input calc.py test_calc.py" ;;
  esac
}
api_host() {
  case "$1" in
    claude) echo api.anthropic.com ;;
    codex|aider) echo api.openai.com ;;
    opencode) if [ -n "${SOAK_OPENCODE_MODEL:-}" ]; then case "$SOAK_OPENCODE_MODEL" in anthropic/*) echo api.anthropic.com ;; *) echo api.openai.com ;; esac
              elif [ -n "$anth" ]; then echo api.anthropic.com; else echo api.openai.com; fi ;;
  esac
}

test_sum=$(sha256sum "$here/fixture/test_calc.py" | cut -d' ' -f1)
: > "$work/rounds.tsv"   # agent round start end exit api_ok solved key_ok tests_ok
deadline=$(( $(date +%s) + minutes * 60 ))
round=0
declare -A missed   # consecutive rounds an agent did not reach its API
while [ "$(date +%s)" -lt "$deadline" ]; do
  live=0
  for a in "${agents[@]}"; do
    [ "$(date +%s)" -lt "$deadline" ] || break
    # a bad key or a down API: stop that agent rather than loop for hours
    [ "${missed[$a]:-0}" -lt 3 ] || continue
    live=1
    round=$((round + 1))
    proj="$work/proj-$round"; out="$work/out-$round.txt"
    mkdir -p "$proj"; find "$here/fixture" -maxdepth 1 -type f -exec cp {} "$proj/" \;
    (cd "$proj" && git init -q -b main && git add . && git -c user.name=soak -c user.email=soak@ovara.invalid commit -q -m fixture)
    start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    echo "=== round $round: $a ($start)"
    ANTHROPIC_API_KEY="$anth" OPENAI_API_KEY="$oai" \
      timeout 1200 "${ovcmd[@]}" box -agent "$a" -profile ci -dir "$d" -ui off -no-commit-back "$proj" -- bash -c "$(agent_cmd "$a")" >"$out" 2>&1 </dev/null
    code=$?
    end=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    ws=$(sed -n 's/^==> workspace kept at //p' "$out" | tail -1)
    solved=no; tests_ok=no; key_ok=yes
    if [ -n "$ws" ] && [ -d "$ws" ]; then
      $SUDO chmod -R a+rX "$ws"
      (cd "$ws" && timeout 120 python3 -I -m unittest -q >/dev/null 2>&1) && solved=yes
      [ "$(sha256sum "$ws/test_calc.py" 2>/dev/null | cut -d' ' -f1)" = "$test_sum" ] && tests_ok=yes
      for k in "$anth" "$oai"; do
        [ -n "$k" ] || continue
        if $SUDO grep -rqF -- "$k" "$ws" "$out" 2>/dev/null; then key_ok=no; fi
      done
      $SUDO rm -rf "$ws"
    else
      for k in "$anth" "$oai"; do [ -n "$k" ] && grep -qF -- "$k" "$out" && key_ok=no; done
    fi
    # the agent's own output is the evidence for a failed round; never keep a key in it
    for k in "$anth" "$oai"; do [ -n "$k" ] && sed -i "s|$(printf '%s' "$k" | sed 's/[|&\\]/\\&/g')|<REDACTED>|g" "$out"; done
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$a" "$round" "$start" "$end" "$code" "$(api_host "$a")" "$solved" "$key_ok" "$tests_ok" >> "$work/rounds.tsv"
    if python3 -I "$here/report.py" -api-ok "$d" "$start" "$end" "$(api_host "$a")"; then missed[$a]=0
    else missed[$a]=$(( ${missed[$a]:-0} + 1 )); [ "${missed[$a]}" -lt 3 ] || echo "    $a did not reach its API 3 rounds running: no more rounds for it"; fi
    echo "    exit=$code solved=$solved key_kept_out=$key_ok tests_untouched=$tests_ok"
    rm -rf "$proj"
  done
  [ "$live" = 1 ] || break
done

doctor=$(ov doctor -dir "$d" 2>&1 | grep -m1 'receipt chain' || true)
echo "=== $doctor"
$SUDO chmod -R a+rX "$d/var"
python3 -I "$here/report.py" "$d" "$work/rounds.tsv" "$doctor" > "$report"
cat "$report"
grep -q '^RESULT: PASS' "$report"
