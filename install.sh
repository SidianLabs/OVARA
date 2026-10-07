#!/bin/sh
# Install the ovara binary (gateway + executor proxy + CLI).
#
#   curl -sSL https://raw.githubusercontent.com/SidianLabs/OVARA/main/install.sh | sh
#
# Downloads the prebuilt binary for your OS/CPU from the latest GitHub
# release and checks its SHA-256. If your platform has no prebuilt binary (or
# OVARA_FROM_SOURCE=1), it builds from source instead (needs git + Go). A
# failed download is an error; it never silently turns into a source build.
#
# Env overrides:
#   OVARA_VERSION      release tag to install (default: latest)
#   OVARA_VERIFY       1 = also verify signed build provenance (needs `gh`)
#   OVARA_INSTALL_DIR  where the binary lands (default: ~/.local/bin)
#   OVARA_FROM_SOURCE  1 = skip downloads, build from source
#   OVARA_BRANCH       branch/tag for source builds (default: main)
#   OVARA_RELEASE_BASE download base URL (testing/mirrors)
set -eu

REPO="SidianLabs/OVARA"
DEST="${OVARA_INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${OVARA_VERSION:-latest}"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

detect() {
  case "$(uname -s)" in
    Linux) os=linux ;;
    Darwin) os=darwin ;;
    MINGW*|MSYS*|CYGWIN*) die "on Windows use install.ps1 (see README)" ;;
    *) os="" ;;
  esac
  case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    arm64|aarch64) arch=arm64 ;;
    *) arch="" ;;
  esac
}

fetch() { # url dest  (HTTPS only; never follow a redirect to plain http)
  if command -v curl >/dev/null; then curl --proto '=https' --tlsv1.2 -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null; then wget -qO "$2" --https-only "$1"
  else die "curl or wget is required"; fi
}

sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

from_release() {
  # Every failure here is fatal. This used to be called as `! from_release`,
  # which both disables `set -e` inside the function and turns ANY failure
  # (rate limit, network blip, 404) into a silent build of main HEAD, even
  # when a version had been pinned. A failed download is now an error the
  # user sees; building from source is an explicit choice.
  case "${OVARA_RELEASE_BASE:-https://}" in
    https://*) ;;
    *) die "OVARA_RELEASE_BASE must be an https:// URL" ;;
  esac
  if [ "$VERSION" = latest ]; then
    # Pre-releases (v0.x) are not "latest" on GitHub; pick the newest release of any kind.
    fetch "https://api.github.com/repos/$REPO/releases?per_page=1" "$tmp/rel.json" \
      || die "could not look up the latest release (network, or GitHub API rate limit). Retry, set OVARA_VERSION=vX.Y.Z, or use OVARA_FROM_SOURCE=1"
    tag=$(sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' "$tmp/rel.json" | head -1)
  else
    tag="$VERSION"
  fi
  [ -n "$tag" ] || die "no release found. Use OVARA_FROM_SOURCE=1 to build from source"
  name="ovara_${tag#v}_${os}_${arch}"
  base="${OVARA_RELEASE_BASE:-https://github.com/$REPO/releases/download}/$tag"
  say "downloading ovara $tag for $os/$arch..."
  fetch "$base/$name.tar.gz" "$tmp/$name.tar.gz" \
    || die "could not download $base/$name.tar.gz (does release $tag have a build for $os/$arch?)"
  fetch "$base/checksums.txt" "$tmp/checksums.txt" || die "release $tag has no checksums.txt; refusing to install unverified binary"
  # "<hash>  <file>" (text mode) or "<hash> *<file>" (binary mode). Exact
  # field match: the file name contains dots, which a regex would treat as
  # wildcards.
  want=$(awk -v f="$name.tar.gz" '$2 == f || $2 == "*" f { print $1; exit }' "$tmp/checksums.txt")
  got=$(sha256 "$tmp/$name.tar.gz")
  [ -n "$want" ] && [ "$want" = "$got" ] || die "checksum mismatch for $name.tar.gz (want $want, got $got)"
  # checksums.txt comes from the same place as the archive, so it proves the
  # download was not corrupted, not who built it. Build provenance does:
  # OVARA_VERIFY=1 requires the GitHub CLI and fails closed.
  if [ "${OVARA_VERIFY:-}" = 1 ]; then
    command -v gh >/dev/null || die "OVARA_VERIFY=1 needs the GitHub CLI (gh) to check build provenance"
    gh attestation verify "$tmp/$name.tar.gz" --repo "$REPO" >/dev/null \
      || die "build provenance check failed for $name.tar.gz; refusing to install"
    say "build provenance verified"
  fi
  tar -xzf "$tmp/$name.tar.gz" -C "$tmp"
  mv "$tmp/$name/ovara" "$tmp/ovara-bin"
}

from_source() {
  command -v git >/dev/null || die "git is required to build from source"
  command -v go  >/dev/null || die "Go 1.25+ is required to build from source (https://go.dev/dl)"
  # A pinned version builds THAT tag, never whatever main happens to be.
  if [ "$VERSION" != latest ]; then branch="$VERSION"; else branch="${OVARA_BRANCH:-main}"; fi
  say "building from source ($branch)..."
  git clone --depth 1 -b "$branch" "https://github.com/$REPO.git" "$tmp/ovara" >/dev/null 2>&1
  (cd "$tmp/ovara/proxy" && CGO_ENABLED=0 go build -trimpath -o "$tmp/ovara-bin" ./cmd/ovara)
}

detect
if [ "${OVARA_FROM_SOURCE:-}" = 1 ]; then
  from_source
elif [ -z "$os" ] || [ -z "$arch" ]; then
  # The only automatic source build: this platform has no prebuilt binary.
  say "no prebuilt binary for $(uname -s)/$(uname -m); building from source"
  from_source
else
  from_release
fi

mkdir -p "$DEST"
mv "$tmp/ovara-bin" "$DEST/ovara"
chmod +x "$DEST/ovara"

cat <<EOF

installed: $DEST/ovara  ($("$DEST/ovara" version 2>/dev/null || echo "version unknown"))
EOF
case ":$PATH:" in *":$DEST:"*) ;; *) say "note: $DEST is not on your PATH; add it, or run $DEST/ovara" ;; esac
cat <<EOF

try it:
  ovara demo                         # 30-second story, no setup
  ovara init mydir                   # keys, config and a sensible default policy
  ovara run -dir mydir               # start it; prints a link to the approval page
  eval "\$(ovara env -dir mydir)"    # then start your agent in this shell
EOF
