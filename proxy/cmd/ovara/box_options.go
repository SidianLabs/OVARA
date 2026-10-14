package main

// `ovara box` options: from flags, from a manifest (-manifest), or both.
// The manifest form is contract C5 of the specification (spec/runtime.md).
// This file is portable so that a manifest can be written anywhere
// (-print-manifest) and run on Linux (-manifest).

import (
	"errors"
	"flag"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"ovara.proxy/internal/sandbox"
)

const (
	boxDefaultUser  = "ovara-agent"
	boxDefaultImage = "ovara-box"

	// profiles (docs/box.md §11.4)
	boxProfileDev    = "dev"
	boxProfileStrict = "strict"
	boxProfileCI     = "ci"

	// tier 1 file systems (box_tier1.go)
	tier1FSIsolated = "isolated"
	tier1FSHost     = "host"
)

// boxOptions is everything `ovara box` is told. Its manifest form is what
// -print-manifest writes and -manifest reads.
type boxOptions struct {
	dir     string
	project string
	cmd     []string
	agent   string // a named agent (ovara agent add NAME); "" is the deployment's default agent

	tier         int
	name         string // tier 1: the network namespace
	user         string // tier 1: the agent's user
	tier1FS      string
	visibleProcs bool
	image        string // tier 2
	pids         int
	memory       string
	cpus         string

	profile        string
	untrusted      bool
	ui             string
	approveTimeout time.Duration
	keep           bool
	noCommitBack   bool
	allowBinary    bool
	ghScope        string
	noGate         bool

	envs     multiFlag
	excludes multiFlag
	mounts   multiFlag
}

func defaultBoxOptions() *boxOptions {
	return &boxOptions{
		tier: 1, name: "ovara-box", user: boxDefaultUser, tier1FS: tier1FSIsolated, image: defaultBoxImage(), pids: 4096,
		profile: boxProfileDev, ui: "127.0.0.1:9090", approveTimeout: 10 * time.Minute, ghScope: sandbox.ScopeRepo,
	}
}

// boxExtra is what a command line says besides the run itself.
type boxExtra struct {
	agentImage    string // -agent-image: a published image, resolved into image and tier before validation
	manifest      string // read the run from this file
	printManifest bool   // write the run down and stop
	events        string // append the events stream to this file
}

// boxFlags binds the flags to o. o's values are the defaults, so a
// manifest's values show as such and a flag typed over them wins.
func boxFlags(o *boxOptions, x *boxExtra) *flag.FlagSet {
	fs := flag.NewFlagSet("box", flag.ContinueOnError)
	fs.StringVar(&o.dir, "dir", o.dir, "Ovara deployment directory (default: ~/.ovara/box of the invoking user; created on first use)")
	fs.IntVar(&o.tier, "tier", o.tier, "isolation: 1 = separate user in a network namespace with its own root file system (see -tier1-fs); 2 = a container (no network but Ovara, no capabilities, read-only root, no host files)")
	fs.StringVar(&o.name, "name", o.name, "tier 1: network namespace name (one box per name at a time)")
	fs.StringVar(&o.user, "user", o.user, "tier 1: unprivileged user the agent runs as (created if missing)")
	fs.StringVar(&o.tier1FS, "tier1-fs", o.tier1FS, "tier 1: isolated = a root file system of its own (the host's system directories read-only, the workspace, a fresh home; nothing of /home, /root, /srv, /opt or the original project); host = the host's file system, where the agent reads whatever its user may (UNSAFE on a machine with secrets)")
	fs.BoolVar(&o.visibleProcs, "allow-visible-procs", o.visibleProcs, "tier 1 isolated: on a kernel before 5.8, which cannot hide other users' processes in the box's /proc, start anyway (the agent can then list every process on the host and its command line); without it such a box is refused")
	fs.StringVar(&o.image, "image", o.image, "tier 2: the box image (a release pins its own published image by digest; build it from box/Dockerfile, or extend it with your agent)")
	fs.StringVar(&x.agentImage, "agent-image", "", "tier 2: the published box image with this agent installed: claude, codex, opencode or aider (implies -tier 2; -image names any other image)")
	fs.IntVar(&o.pids, "pids", o.pids, "tier 2: most processes the box may have at once")
	fs.StringVar(&o.memory, "memory", o.memory, "tier 2: memory limit for the box (docker syntax, e.g. 8g; default none)")
	fs.StringVar(&o.cpus, "cpus", o.cpus, "tier 2: CPU limit for the box (e.g. 2; default none)")
	fs.StringVar(&o.profile, "profile", o.profile, "dev: installs are free; strict: a dependency not in the project's lockfiles pauses once with its name and version, and npm install scripts are off (docs/box.md §9); ci: strict, and no one answers: anything policy would pause (a request, a new package, a command, the commit-back) is refused at once (§11.4)")
	fs.BoolVar(&o.untrusted, "untrusted-lockfiles", o.untrusted, "strict or ci: the project's lockfiles are not trusted (a repository you are reviewing, not your own): nothing they pin is let through without a question")
	fs.StringVar(&o.ui, "ui", o.ui, "approval page address (loopback only; \"off\" to disable)")
	fs.DurationVar(&o.approveTimeout, "approve-timeout", o.approveTimeout, "how long the commit-back waits for a person")
	fs.BoolVar(&o.keep, "keep", o.keep, "keep the workspace after the run (default: kept only when something went wrong)")
	fs.BoolVar(&o.noCommitBack, "no-commit-back", o.noCommitBack, "do not offer to bring changes back; keep the workspace")
	fs.BoolVar(&o.allowBinary, "allow-binary", o.allowBinary, "let binary files the agent added or changed come back (by default they stay in the workspace: a diff cannot show what is in them)")
	fs.StringVar(&o.ghScope, "github-scope", o.ghScope, "repo: the GitHub key only goes with requests about the project's own repository (from its origin remote); all: every request to GitHub gets it")
	fs.BoolVar(&o.noGate, "no-command-gate", o.noGate, "do not check the agent's commands against policy (the network and file boundaries still hold)")
	fs.StringVar(&o.agent, "agent", o.agent, "run the agent as this named agent (ovara agent add NAME), with its own proxy token, so receipts and approvals name it and ovara kill can stop it alone")
	fs.Var(&o.envs, "env", "extra NAME=value for the agent (repeatable; values that look like keys are refused)")
	fs.Var(&o.excludes, "exclude", "extra path glob to leave out of the workspace (repeatable; .ovaraignore is read too)")
	fs.Var(&o.mounts, "mount", "SRC:DST, a host path mounted READ-ONLY into the box (repeatable; secret locations are refused; not with -tier1-fs host)")
	fs.StringVar(&x.manifest, "manifest", "", "read the run from this manifest file (spec/runtime.md); a flag given here wins over it, a project directory or -- command given here replaces its")
	fs.BoolVar(&x.printManifest, "print-manifest", false, "write the run these flags describe as a manifest on stdout and stop (no root needed; -manifest FILE runs it)")
	fs.StringVar(&x.events, "events", "", "append the run's events to this file, one JSON line each, from run.created to run.finished (spec/runtime.md)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: ovara box [flags] <project-dir> -- <agent command...>")
		fmt.Fprintln(os.Stderr, "       ovara box -manifest FILE [flags] [<project-dir>] [-- <agent command...>]")
		fs.PrintDefaults()
	}
	return fs
}

// parseBoxArgs reads a command line, and the manifest it names, into the
// run's options.
func parseBoxArgs(args []string) (*boxOptions, *boxExtra, error) {
	o, x := defaultBoxOptions(), &boxExtra{}
	fs := boxFlags(o, x)
	if err := fs.Parse(args); err != nil {
		return nil, nil, err
	}
	if x.manifest != "" {
		m, err := sandbox.Load(x.manifest)
		if err != nil {
			return nil, nil, err
		}
		// the manifest's values are the defaults of a second parse: what
		// was typed wins, what was not keeps the manifest's value
		o, x = defaultBoxOptions(), &boxExtra{}
		o.applyManifest(m)
		fs = boxFlags(o, x)
		if err := fs.Parse(args); err != nil {
			return nil, nil, err
		}
	}
	if x.agentImage != "" {
		set := map[string]bool{}
		fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
		img, err := agentImage(x.agentImage)
		if err != nil {
			return nil, nil, err
		}
		if set["image"] {
			return nil, nil, errors.New("-agent-image and -image both name the image: use one")
		}
		if set["tier"] && o.tier != 2 {
			return nil, nil, errors.New("-agent-image is for tier 2 (a container image)")
		}
		o.tier, o.image = 2, img
	}
	project, cmd, err := boxPositional(args, fs)
	if err != nil {
		fs.Usage()
		return nil, nil, err
	}
	if project != "" {
		o.project = project
	}
	if len(cmd) > 0 {
		o.cmd = cmd
	}
	if o.project == "" || len(o.cmd) == 0 {
		fs.Usage()
		return nil, nil, errors.New("need a project directory, then --, then the agent command")
	}
	if err := o.validate(); err != nil {
		return nil, nil, err
	}
	return o, x, nil
}

// boxPositional splits what follows the flags: "<project-dir> -- <agent
// command...>", either part optional with a manifest. A "--" right after
// the flags (which the flag package consumes) starts the command.
func boxPositional(args []string, fs *flag.FlagSet) (project string, cmd []string, err error) {
	rest := fs.Args()
	if n := len(args) - len(rest); n > 0 && args[n-1] == "--" {
		if len(rest) == 0 {
			return "", nil, errors.New("nothing after --: the agent command")
		}
		return "", rest, nil
	}
	switch {
	case len(rest) == 0:
		return "", nil, nil
	case len(rest) == 1:
		return rest[0], nil, nil
	case rest[1] != "--" || len(rest) == 2:
		return "", nil, errors.New("want: <project-dir> -- <agent command...>")
	}
	return rest[0], rest[2:], nil
}

// validate checks what needs neither root nor Linux: the manifest's rules,
// in the flags' words.
func (o *boxOptions) validate() error {
	if o.tier != 1 && o.tier != 2 {
		return fmt.Errorf("-tier %d: want 1 or 2", o.tier)
	}
	if o.profile != boxProfileDev && o.profile != boxProfileStrict && o.profile != boxProfileCI {
		return fmt.Errorf("-profile %s: want dev, strict or ci", o.profile)
	}
	if o.untrusted && o.profile == boxProfileDev {
		return errors.New("-untrusted-lockfiles is for -profile strict, or ci (the dev profile asks about no package)")
	}
	if o.tier1FS != tier1FSIsolated && o.tier1FS != tier1FSHost {
		return fmt.Errorf("-tier1-fs %s: want isolated or host", o.tier1FS)
	}
	if o.tier == 1 && o.tier1FS == tier1FSHost && len(o.mounts) > 0 {
		return errors.New("-mount needs a box file system: with -tier1-fs host the agent already sees the host's files its user may read")
	}
	for _, kv := range o.envs {
		k, _, ok := strings.Cut(kv, "=")
		if !ok {
			return fmt.Errorf("-env %q: want NAME=value", kv)
		}
		if sandbox.KeyLikeName.MatchString(k) {
			return fmt.Errorf("-env %s: looks like a secret; put real keys in Ovara's environment (proxy.json credentials), never in the box", k)
		}
	}
	if o.ghScope != sandbox.ScopeRepo && o.ghScope != sandbox.ScopeAll {
		return fmt.Errorf("-github-scope %s: want repo or all", o.ghScope)
	}
	return nil
}

// manifest writes o down: what -print-manifest prints and run.created
// carries. Only the chosen tier's isolation is written.
func (o *boxOptions) manifest() *sandbox.Manifest {
	m := &sandbox.Manifest{
		Version:            sandbox.Version,
		Tier:               o.tier,
		Workspace:          sandbox.Workspace{Source: o.project, Exclude: o.excludes},
		Agent:              sandbox.Agent{Name: o.agent, Command: o.cmd, Env: envMap(o.envs)},
		Deployment:         o.dir,
		Profile:            o.profile,
		UntrustedLockfiles: o.untrusted,
		Mounts:             o.mounts,
		Credentials:        sandbox.Credentials{GitHubScope: o.ghScope},
		CommitBack: sandbox.CommitBack{
			Disabled: o.noCommitBack, AllowBinary: o.allowBinary, ApproveTimeout: o.approveTimeout.String(), KeepWorkspace: o.keep,
		},
		UI: o.ui,
	}
	if o.tier == 2 {
		m.Isolation = sandbox.Isolation{Image: o.image}
		m.Limits = sandbox.Limits{PIDs: o.pids, Memory: o.memory, CPUs: o.cpus}
	} else {
		m.Isolation = sandbox.Isolation{Name: o.name, User: o.user, RootFS: o.tier1FS, AllowVisibleProcs: o.visibleProcs}
	}
	if o.noGate {
		off := false
		m.CommandGate = &off
	}
	return m
}

// applyManifest sets o from m (already validated). Members m leaves out
// keep o's defaults.
func (o *boxOptions) applyManifest(m *sandbox.Manifest) {
	o.project, o.cmd, o.agent = m.Workspace.Source, m.Agent.Command, m.Agent.Name
	o.excludes = append(multiFlag(nil), m.Workspace.Exclude...)
	o.envs = nil
	for _, k := range slices.Sorted(maps.Keys(m.Agent.Env)) {
		o.envs = append(o.envs, k+"="+m.Agent.Env[k])
	}
	if m.Tier != 0 {
		o.tier = m.Tier
	}
	if m.Deployment != "" {
		o.dir = m.Deployment
	}
	if m.Profile != "" {
		o.profile = m.Profile
	}
	o.untrusted = m.UntrustedLockfiles
	if m.Isolation.Name != "" {
		o.name = m.Isolation.Name
	}
	if m.Isolation.User != "" {
		o.user = m.Isolation.User
	}
	if m.Isolation.RootFS != "" {
		o.tier1FS = m.Isolation.RootFS
	}
	o.visibleProcs = m.Isolation.AllowVisibleProcs
	if m.Isolation.Image != "" {
		o.image = m.Isolation.Image
	}
	o.mounts = append(multiFlag(nil), m.Mounts...)
	if m.Limits.PIDs != 0 {
		o.pids = m.Limits.PIDs
	}
	o.memory, o.cpus = m.Limits.Memory, m.Limits.CPUs
	if m.Credentials.GitHubScope != "" {
		o.ghScope = m.Credentials.GitHubScope
	}
	o.noCommitBack, o.allowBinary, o.keep = m.CommitBack.Disabled, m.CommitBack.AllowBinary, m.CommitBack.KeepWorkspace
	if m.CommitBack.ApproveTimeout != "" {
		o.approveTimeout, _ = time.ParseDuration(m.CommitBack.ApproveTimeout) // validated with the manifest
	}
	if m.CommandGate != nil {
		o.noGate = !*m.CommandGate
	}
	if m.UI != "" {
		o.ui = m.UI
	}
}

// envMap turns NAME=value pairs into a map (a later pair wins, as -env
// does); nil when there are none.
func envMap(envs []string) map[string]string {
	if len(envs) == 0 {
		return nil
	}
	m := make(map[string]string, len(envs))
	for _, kv := range envs {
		k, v, _ := strings.Cut(kv, "=")
		m[k] = v
	}
	return m
}

// printManifest writes the run o describes on stdout.
func printManifest(o *boxOptions) error {
	out, err := o.manifest().Encode()
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(out)
	return err
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// boxAgents are the agents with a published image (box/agents/Dockerfile).
var boxAgents = map[string]bool{"claude": true, "codex": true, "opencode": true, "aider": true}

// agentImage names the box image with agent installed: the release's
// published image for this version, or the local development build.
func agentImage(agent string) (string, error) {
	if !boxAgents[agent] {
		return "", fmt.Errorf("-agent-image %q: want claude, codex, opencode or aider (or -image for your own image)", agent)
	}
	if repo, _, ok := strings.Cut(boxImage, "@"); ok && repo != "" && version != devVersion {
		return repo + "-" + agent + ":" + version, nil
	}
	return boxDefaultImage + "-" + agent, nil
}

// defaultBoxImage is the image this build was released with, or the local
// development image.
func defaultBoxImage() string {
	if boxImage != "" {
		return boxImage
	}
	return boxDefaultImage
}
