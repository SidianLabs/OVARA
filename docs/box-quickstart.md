# Ovara Box quickstart

Run a coding agent in a box where every way out goes through Ovara: the
network through its proxy, your files only as a copy, every command it
starts checked against a policy, and its changes back only as a branch you
review. Linux only for now (macOS and Windows: run it inside a Linux VM).
`docs/box.md` has the design and the limits.

## 1. Install

From a release:

```bash
curl -sSL https://raw.githubusercontent.com/SidianLabs/OVARA/main/install.sh | sh
sudo install ~/.local/bin/ovara /usr/local/bin/ovara
ovara version
```

`install.sh` puts `ovara` in `~/.local/bin`, which `sudo` does not search;
the second line puts it where `sudo ovara` finds it.

Or from source (Go 1.25+):

```bash
git clone https://github.com/SidianLabs/OVARA && cd OVARA/proxy
go build -o ovara ./cmd/ovara && sudo install ovara /usr/local/bin/
```

You need root (`sudo`) to make a box. For the container tier you also need
Docker. A source build has no published image to pin, so build it once:
`docker build -t ovara-box box/` from the repository root.

## 2. A first box, with a shell

```bash
sudo ovara box ./myrepo -- bash
```

Inside, look around: you are user `ovara-agent` in a copy of the project
(history kept, `.env` and key files left out), the network reaches only
Ovara, and `sudo` is refused. Change a file, then `exit`. Ovara shows the
diff and waits for you to approve bringing it back (next section).

The first run creates Ovara's settings in `~/.ovara/box`.

## 3. Answer what the box asks

Anything the policy pauses (a request to a site outside the trusted list, a
`rm -rf`, bringing changes back) waits for you. Either open the link
`ovara box` prints (a local page with Approve and Deny), or, in a second
terminal:

```bash
sudo ovara approvals -dir ~/.ovara/box
sudo ovara approve apr_... -dir ~/.ovara/box
sudo ovara deny apr_... -dir ~/.ovara/box
```

Or answer each one as it comes:

```bash
sudo ovara watch -dir ~/.ovara/box
```

## 4. What comes back

Approved changes land on a new branch of your real repository; your
working tree and current branch are not touched:

```bash
cd myrepo
git branch --list 'ovara/box-*'
git diff main...ovara/box-20261010-120000
git merge ovara/box-20261010-120000
```

Paths the policy keeps out (CI workflows, `.git/`) never come back.

## 5. An agent, in the container tier

Keys stay with Ovara: the agent only ever sees a placeholder, and Ovara
puts the real key on the request at the proxy. `sudo` drops your
environment, so name the keys it should keep:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
sudo --preserve-env=ANTHROPIC_API_KEY ovara box -agent claude ./myrepo -- claude
```

`-agent` (claude, codex, opencode or aider) uses a ready image with that
agent installed and runs it in the container tier: no network but Ovara,
no capabilities, a read-only root, nothing of your machine but the copy.
For another agent, extend the box image and pass it with `-image`.

The same agent, as a user on your machine instead of in a container:

```bash
sudo --preserve-env=OPENAI_API_KEY ovara box -tier 1 ./myrepo -- codex
```

## 6. Stricter, or unattended

```bash
sudo ovara box -profile strict ./myrepo -- bash
sudo ovara box -profile ci ./myrepo -- ./run-agent.sh
```

- `strict`: a package the project's lockfiles do not pin pauses once, by
  name and version, before it downloads; npm install scripts are off.
- `ci`: strict, and nobody answers: anything that would pause is refused
  at once, and changes stay in the workspace unless your policy allows
  them back.

## 7. See what happened

```bash
sudo ovara log -dir ~/.ovara/box
```

Every request, approval and refusal, from a signed, hash-chained record
that shows whether it has been edited.

## If something goes wrong

- `box image "ovara-box" not found`: a source build; run
  `docker build -t ovara-box box/` (and, for `-agent`,
  `docker build --build-arg AGENT=claude -t ovara-box-claude box/agents`).
- `ovara box needs root`: run it with `sudo`; the agent itself never runs
  as root.
- A request you expected to work is refused: `sudo ovara log -dir
  ~/.ovara/box` says which rule decided; `ovara policy -dir ~/.ovara/box`
  explains the rules.
