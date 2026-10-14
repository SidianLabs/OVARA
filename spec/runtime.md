# C5 — The sandbox runtime: manifest, events, summary (spec 0.1)

`ovara box` is the reference runtime of this contract: it takes a project
and an agent command, builds a box around them (a copy of the project with
the secrets left out, no network but Ovara, every program checked at exec),
runs the agent, and brings the changes back through a person. The contract
is the shape of that exchange, so that a CI job, an orchestrator or a
service can drive a box without reading its terminal:

- the **manifest**: the run, written down
  ([`schemas/manifest.schema.json`](schemas/manifest.schema.json));
- the **events stream**: what happens, as it happens
  ([`schemas/event.schema.json`](schemas/event.schema.json));
- the **summary**: how it ended; the last event's payload.

The in-process form (create, start, events, stop, finish as calls on a Go
interface) is not in 0.1: the command is the interface, and these three
documents are its arguments and its results. The in-process form will be
added without changing them. Go types: `proxy/internal/sandbox`.

## 1. The manifest

A JSON document with `version` `"0.1"`. `ovara box -print-manifest [flags]
<project-dir> -- <agent command>` writes the manifest its command line
describes and stops (no root, any platform); `ovara box -manifest FILE`
runs one. Next to `-manifest`, a flag wins over the file's value, and a
project directory or a `--` command replaces the file's. Unknown members
are refused, so a misspelt member never silently means the default.

| Member | Meaning |
|---|---|
| `version` | required: `"0.1"` |
| `tier` | `1` (default): a separate user in a network namespace with its own root file system; `2`: a container |
| `workspace.source` | required: the project directory; the agent works on a copy |
| `workspace.exclude` | extra path globs left out of the copy (`.ovaraignore` is read too) |
| `agent.command` | required: the agent's command line, program first |
| `agent.name` | a named agent (`ovara agent add NAME`): its own proxy token, so receipts and approvals name it |
| `agent.env` | extra variables for the agent; a name containing key, token, secret, password, passwd or credential is refused, whatever the value |
| `deployment` | Ovara's directory for the run (policy, keys, receipts); default `~/.ovara/box` |
| `profile` | `dev` (default): installs are free; `strict`: a dependency the project's lockfiles do not pin pauses once |
| `untrusted_lockfiles` | strict: trust nothing the lockfiles pin |
| `isolation` | tier 1: `name` (network namespace), `user`, `root_fs` (`isolated`, default, or `host`), `allow_visible_procs`; tier 2: `image` |
| `mounts` | read-only `SRC:DST` pairs; secret and system locations are refused by the launcher |
| `limits` | tier 2: `pids`, `memory`, `cpus` |
| `credentials.github_scope` | `repo` (default): the GitHub key goes only with requests about the project's own repository; `all` |
| `commit_back` | `disabled`, `allow_binary`, `approve_timeout` (a duration), `keep_workspace` |
| `command_gate` | `false` runs without the check on every program the agent starts; absent means on |
| `ui` | the approval page address (loopback only) or `off` |

A manifest carries no secret. Credentials live in Ovara's deployment, bound
to hosts and injected on the way out (`docs/GUARANTEES.md` §3); the
environment a manifest gives the agent is configuration. A manifest in a
repository therefore says what the agent may do, not what it may use.

```json
{
  "version": "0.1",
  "tier": 2,
  "workspace": {"source": ".", "exclude": ["dist/*"]},
  "agent": {"name": "reviewer", "command": ["opencode", "run", "fix the failing tests"]},
  "profile": "strict",
  "isolation": {"image": "ghcr.io/example/box@sha256:…"},
  "limits": {"pids": 2048, "memory": "8g", "cpus": "2"},
  "commit_back": {"approve_timeout": "15m"},
  "ui": "off"
}
```

## 2. The events stream

`ovara box -events FILE` appends one JSON line per event to FILE (created
owner-only), as it happens. Every line has `v` (1), `time` (RFC 3339,
UTC), `run_id` and `event`; the other members belong to the events that
use them. Runs may share a file: `run_id` tells them apart.

| Event | When | Carries |
|---|---|---|
| `run.created` | the run exists | `manifest`: the run written down, defaults resolved |
| `workspace.copied` | the project's copy is in place | `workspace`: its path |
| `proxy.started` | Ovara is up for this run | |
| `agent.started` | the agent command is launched | `command` |
| `command.allowed` | a program the agent started, allowed by policy | `command` |
| `command.refused` | refused by policy, or the gateway could not be asked | `command` |
| `command.paused` | waiting for a person | `command`, `approval_id` |
| `command.approved` | approved, so it runs | `command`, `approval_id` |
| `command.not_approved` | not run | `command`, `approval_id`, `status` (denied, expired, timed out) |
| `agent.exited` | the agent is done | `code` |
| `commit_back.disabled` | nothing is offered (`commit_back.disabled` in the manifest) | |
| `commit_back.nothing` | the agent changed nothing | |
| `commit_back.kept` | every changed path is kept out by policy | |
| `commit_back.refused` | policy refuses the commit-back | |
| `commit_back.waiting` | a person is reading the diff | `approval_id`, `files` |
| `commit_back.not_approved` | nothing comes back | `approval_id`, `status` |
| `commit_back.landed` | the changes are on a branch of the project | `branch`, `commit`, `files` |
| `run.finished` | always the last event, whatever happened | `summary`; `error` when the run failed |

The command events come from the command gate, so a run with
`command_gate: false` has none. Commands are reported as run (the raw
command line), not in the canonical form policy matches (C1): the stream
is for the person's tools, policy for the gate.

## 3. The summary

`run.finished` carries it:

- `outcome`: `clean` (the agent ran, and whatever came back is on its
  branch; the workspace is removed), `kept` (something is left for a
  person; the workspace stays), `failed` (the launcher could not finish;
  `error` says why);
- `exit_code`: the agent's;
- `requests`: `allowed`, `paused`, `denied` through the proxy during the
  run, and `hosts`, the distinct hosts named;
- `commands`: `allowed`, `paused`, `approved`, `denied` through the command
  gate; absent when the gate was off;
- `commit_back`: the `commit_back.*` event that ended it, after the dot, or
  empty when the run failed before that; `branch` and `commit` when it
  landed.

## 4. Conformance

`proxy/internal/sandbox`: `TestParseValidManifest`, `TestParseRefusals`,
`TestEventsAreJSONLinesWithTheFixedMembers`,
`TestOpenEventsAppendsToAnOwnerOnlyFile`, `TestSpecSchemasMatchTheCode`
(the schemas name exactly the members the code has, and every event name).
`proxy/cmd/ovara`: `TestBoxArgs_FlagsAndPositional`,
`TestBoxArgs_ManifestWithOverrides`, `TestBoxOptions_ManifestRoundTrip`,
`TestBoxPrintManifest` (flags and manifest describe the same run, both
ways). End to end: `tests/box/box.sh` ("the events stream"), in CI as the
`box` and `box-tier2` jobs: a real run's stream starts with `run.created`
carrying the manifest, names the refused and the paused commands, the
branch that landed, and ends with `run.finished`.
