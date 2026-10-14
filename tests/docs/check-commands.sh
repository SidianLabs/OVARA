#!/usr/bin/env bash
# Every `ovara` command line in the user docs must name a real command and
# real flags of the binary built from this checkout, so the quickstart
# cannot drift from the code.
#   tests/docs/check-commands.sh [ovara-binary]
set -u
here="$(cd "$(dirname "$0")" && pwd)"; repo="$(cd "$here/../.." && pwd)"
bin="${1:-}"
if [ -z "$bin" ]; then
  bin="$(mktemp -d)/ovara"
  (cd "$repo/proxy" && CGO_ENABLED=0 go build -o "$bin" ./cmd/ovara) || { echo "BUILD FAILED"; exit 1; }
fi
docs=("$repo/docs/box-quickstart.md")
fail=0; n=0
check() { # file line
  local f="$1" line="$2"
  # the words after "ovara": the subcommand, then flags
  local rest="${line#*ovara }"
  read -r -a w <<< "$rest"
  local sub="${w[0]}"
  case "$sub" in version|init|run|box|demo|env|policy|watch|approvals|log|approve|deny|doctor) ;;
    *) echo "FAIL  $(basename "$f"): unknown command 'ovara $sub' in: $line"; fail=$((fail+1)); return ;;
  esac
  local help; help="$("$bin" "$sub" -h 2>&1)"
  for word in "${w[@]:1}"; do
    case "$word" in
      --) break ;;                          # the agent's own command follows
      -*) local flag="${word%%=*}"; flag="-${flag#-}"; flag="${flag#-}"
          echo "$help" | grep -qE "^  -${flag#-}( |$)|\[-${flag#-}( |\])" || { echo "FAIL  $(basename "$f"): 'ovara $sub' has no flag $word in: $line"; fail=$((fail+1)); } ;;
    esac
  done
  n=$((n+1))
}
for f in "${docs[@]}"; do
  in=0
  while IFS= read -r line; do
    case "$line" in '```bash'*) in=1; continue ;; '```'*) in=0; continue ;; esac
    [ $in = 1 ] || continue
    case "$line" in *"ovara "*) ;; *) continue ;; esac
    case "$line" in *"install"*"ovara"*|*"go build"*|*"github.com"*) continue ;; esac
    check "$f" "$line"
  done < "$f"
done
echo "checked $n ovara command line(s); $fail problem(s)"
[ $fail = 0 ]
