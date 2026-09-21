#!/bin/sh
# Install the Ovara unified binary (gateway + executor proxy).
#
#   curl -sSL https://raw.githubusercontent.com/SidianLabs/OVARA/main/install.sh | sh
#
# Env overrides:
#   OVARA_BRANCH       branch/tag to build (default: main)
#   OVARA_INSTALL_DIR  where the binary lands (default: ~/.local/bin)
set -eu

REPO="https://github.com/SidianLabs/OVARA.git"
BRANCH="${OVARA_BRANCH:-main}"
DEST="${OVARA_INSTALL_DIR:-$HOME/.local/bin}"

command -v git >/dev/null || { echo "error: git is required" >&2; exit 1; }
command -v go  >/dev/null || { echo "error: Go 1.25+ is required (https://go.dev/dl)" >&2; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "cloning $REPO ($BRANCH)..."
git clone --depth 1 -b "$BRANCH" "$REPO" "$tmp/ovara" >/dev/null 2>&1

echo "building..."
(cd "$tmp/ovara/proxy" && CGO_ENABLED=0 go build -trimpath -o "$tmp/ovara-bin" ./cmd/ovara)

mkdir -p "$DEST"
mv "$tmp/ovara-bin" "$DEST/ovara"
chmod +x "$DEST/ovara"

cat <<EOF

installed: $DEST/ovara

try it:
  ovara demo                 # zero-setup proof: allow + deny, both receipted
  ovara init mydir           # generate keys + configs
  ovara run -dir mydir       # gateway + proxy in one process

then point your agent at it:
  export HTTPS_PROXY=http://localhost:9443
  export SSL_CERT_FILE=mydir/var/ca.pem
EOF
