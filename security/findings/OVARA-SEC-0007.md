# OVARA-SEC-0007 — netns mode shares host procfs/fs/IPC/unix sockets; credential leakage via /proc

**Severity:** MEDIUM
**Component:** proxy/scripts/setup-egress-boundary.sh (netns mode),
docs (isolation claims)
**Status:** CONFIRMED LIVE (partial — procfs visibility verified)

## Evidence
`ip netns exec` isolates ONLY the network stack. Verified: inside
`audit-ns`, `/proc/*/environ` and host mounts are fully visible. The
scripted recipe drops to `--reuid 1000` but the proxy runs as the
operator's uid — same-uid agents can read `/proc/<proxy-pid>/environ`,
which contains expanded secrets (e.g. `GITHUB_TOKEN=...` exported into
`ovara run`).

Attack paths (reviewer + live):
- Same-uid agent → reads proxy environ → real credentials, plus CA key
  path, receipt key path (both readable by that uid).
- Host unix sockets (`/run/dbus/system_bus_socket` 0666, docker.sock if
  world-accessible) — filesystem sockets are NOT netns-scoped.
- World-readable host files (~/.gitconfig tokens, /etc) — readable and
  exfiltratable THROUGH the allowed proxy path.
- `setpriv --bounding-set` is a printed hint, not enforced; it does not
  survive setuid binaries (script's own caveat).
- AF_PACKET (CAP_NET_RAW) bypasses the `inet output` hook entirely —
  in-ns nft sees nothing; only host INPUT/FORWARD posture catches it.

## Root cause
netns is a network boundary only; the product docs describe a broader
"agent environment" boundary. No mount/PID/IPC namespace isolation, no
cap enforcement mechanism, no hidepid.

## Security impact
In the documented netns deployment, an agent running as the proxy's uid
obtains every injected credential — defeating the core custody claim for
the lightest-weight deployment mode. Fail-closed mitigations exist
(different uid, hidepid=2, container runtime) but are operator-side.

## Proposed fix
- Script must verify agent's `CapBnd` at launch (refuse if NET_ADMIN/
  NET_RAW present) — or wrap with `unshare -Urn`+`no_new_privs`.
- Document netns as NETWORK-ONLY isolation; recommend docker/container
  mode (own PID+mount ns) for real separation.
- Recommend `hidepid=2` on /proc and per-uid separation in the recipe;
  prefer creds via files with 0600 perms rather than env (env is
  inherited AND proc-visible).
- `ovara doctor` should flag shared-uid + procfs visibility.

## Residual risk
netns mode will never equal container isolation; docs must say so
plainly rather than imply parity.
