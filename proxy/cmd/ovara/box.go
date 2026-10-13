//go:build linux

package main

// `ovara box`: run an agent in a box whose only exits go through Ovara.
//
//   ovara box [flags] <project-dir> -- <agent command...>
//
// What it does, in order (docs/box.md §6):
//   1. `ovara init` the deployment if it is missing;
//   2. copy the project into a workspace (a real clone, history included,
//      secrets left out, the host's uncommitted changes carried over);
//   3. start `ovara run` (tier 1: with a netns boundary) so the box has no
//      network path except the proxy;
//   4. run the agent inside the box as an unprivileged user that is not the
//      one running Ovara, with the proxy environment and no keys;
//   5. every program the agent starts is stopped at exec and checked
//      against policy (action_type shell): allowed, killed, or held for a
//      person (internal/boxgate);
//   6. when it exits, bring its changes back as a commit on a new branch of
//      the real repository, after a person has read the diff and a policy
//      has had its say on each path.
//
// Tier 1: a separate user in a network namespace on the host, with a root
// file system of its own: the host's system directories read-only, the
// workspace, a fresh home, and nothing else of the host (box_tier1.go).
// -tier1-fs host gives it the host's file system instead.
// Tier 2: a container (box image) with no network interface but loopback,
// no capabilities, a read-only root, and nothing of the host mounted except
// the workspace and a fresh home. Its proxy and command gate reach the host
// over Unix sockets only root inside the container can open (boxinit.go).
// Both need root on the host today.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"maps"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"ovara.proxy/internal/boxgate"
	"ovara.proxy/internal/config"
	"ovara.proxy/internal/gateway"
	"ovara.proxy/internal/lockfiles"
	"ovara.proxy/internal/workspace"
)

const (
	boxDefaultUser = "ovara-agent"
	boxRunsRoot    = "/var/lib/ovara/runs"
	boxPreviewMax  = 64 << 10

	// tier 2: the box image's agent user, and where things are inside it
	boxContainerUID  = 10001
	boxDefaultImage  = "ovara-box"
	boxInWork        = "/work"
	boxInHome        = "/home/agent"
	boxInCA          = "/etc/ovara/ca.pem"
	boxInBinary      = "/opt/ovara/ovara"
	boxContainerName = "ovara-box-"

	// profiles (docs/box.md §11.4)
	boxProfileDev    = "dev"
	boxProfileStrict = "strict"

	// run outcomes
	outcomeClean  = "clean"  // everything came back or nothing changed: the workspace is removed
	outcomeKept   = "kept"   // something is left for a person: the workspace stays
	outcomeFailed = "failed" // an error on our side: the workspace stays

	// approval states (the gateway's decisions are in commitback.go)
	approvalApproved = "approved"
	approvalError    = "error"

	// command-gate tallies
	countAllowed  = "allowed"
	countApproved = "approved"
	countDenied   = "denied"
)

var keyLikeName = regexp.MustCompile(`(?i)(key|token|secret|password|passwd|credential)`)

// boxAgent is what both tiers need to start the agent.
type boxAgent struct {
	dir      string
	cfg      *config.Config
	ws       *workspace.Workspace
	runID    string
	runDir   string
	home     string
	caPub    string
	port     string
	envs     []string
	cmd      []string
	gate     *commandGate
	noGate   bool
	sigs     chan os.Signal
	user     string   // tier 1
	uid, gid int      // tier 1: the agent user's
	name     string   // tier 1: netns name
	tier1FS  string   // tier 1: isolated or host
	image    string   // tier 2
	mounts   []string // SRC:DST, read-only (tier 1 isolated, tier 2)
	pids     int      // tier 2
	memory   string   // tier 2
	cpus     string   // tier 2
	selfPath string
}

func cmdBox(args []string) error {
	fs := flag.NewFlagSet("box", flag.ContinueOnError)
	dir := fs.String("dir", "", "Ovara deployment directory (default: ~/.ovara/box of the invoking user; created on first use)")
	tier := fs.Int("tier", 1, "isolation: 1 = separate user in a network namespace with its own root file system (see -tier1-fs); 2 = a container (no network but Ovara, no capabilities, read-only root, no host files)")
	name := fs.String("name", "ovara-box", "tier 1: network namespace name (one box per name at a time)")
	agentUser := fs.String("user", boxDefaultUser, "tier 1: unprivileged user the agent runs as (created if missing)")
	tier1FS := fs.String("tier1-fs", tier1FSIsolated, "tier 1: isolated = a root file system of its own (the host's system directories read-only, the workspace, a fresh home; nothing of /home, /root, /srv, /opt or the original project); host = the host's file system, where the agent reads whatever its user may (UNSAFE on a machine with secrets)")
	image := fs.String("image", boxDefaultImage, "tier 2: the box image (build it from box/Dockerfile; extend it with your agent)")
	pids := fs.Int("pids", 4096, "tier 2: most processes the box may have at once")
	memory := fs.String("memory", "", "tier 2: memory limit for the box (docker syntax, e.g. 8g; default none)")
	cpus := fs.String("cpus", "", "tier 2: CPU limit for the box (e.g. 2; default none)")
	profile := fs.String("profile", boxProfileDev, "dev: installs are free; strict: a dependency not in the project's lockfiles pauses once with its name and version, and npm install scripts are off (docs/box.md §9)")
	untrustedLockfiles := fs.Bool("untrusted-lockfiles", false, "strict: the project's lockfiles are not trusted (a repository you are reviewing, not your own): nothing they pin is let through without a question")
	uiAddr := fs.String("ui", "127.0.0.1:9090", "approval page address (loopback only; \"off\" to disable)")
	approveTimeout := fs.Duration("approve-timeout", 10*time.Minute, "how long the commit-back waits for a person")
	keep := fs.Bool("keep", false, "keep the workspace after the run (default: kept only when something went wrong)")
	noCommitBack := fs.Bool("no-commit-back", false, "do not offer to bring changes back; keep the workspace")
	allowBinary := fs.Bool("allow-binary", false, "let binary files the agent added or changed come back (by default they stay in the workspace: a diff cannot show what is in them)")
	noGate := fs.Bool("no-command-gate", false, "do not check the agent's commands against policy (the network and file boundaries still hold)")
	var envs, excludes, mounts multiFlag
	fs.Var(&envs, "env", "extra NAME=value for the agent (repeatable; values that look like keys are refused)")
	fs.Var(&excludes, "exclude", "extra path glob to leave out of the workspace (repeatable; .ovaraignore is read too)")
	fs.Var(&mounts, "mount", "SRC:DST, a host path mounted READ-ONLY into the box (repeatable; secret locations are refused; not with -tier1-fs host)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: ovara box [flags] <project-dir> -- <agent command...>")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) < 3 || rest[1] != "--" {
		fs.Usage()
		return errors.New("need a project directory, then --, then the agent command")
	}
	project, agentCmd := rest[0], rest[2:]
	if runtime.GOOS != "linux" {
		return errors.New("ovara box needs Linux (a network namespace); on macOS/Windows run it inside a Linux VM")
	}
	if *tier != 1 && *tier != 2 {
		return fmt.Errorf("-tier %d: want 1 or 2", *tier)
	}
	if *profile != boxProfileDev && *profile != boxProfileStrict {
		return fmt.Errorf("-profile %s: want dev or strict", *profile)
	}
	if *untrustedLockfiles && *profile != boxProfileStrict {
		return errors.New("-untrusted-lockfiles is for -profile strict (the dev profile asks about no package)")
	}
	if os.Geteuid() != 0 {
		return errors.New("ovara box needs root (tier 1: the network namespace; tier 2: handing the workspace to the box's user and keeping Ovara's sockets out of its reach): run it with sudo; the agent itself runs as an unprivileged user")
	}
	if *tier1FS != tier1FSIsolated && *tier1FS != tier1FSHost {
		return fmt.Errorf("-tier1-fs %s: want isolated or host", *tier1FS)
	}
	if *tier == 1 && *tier1FS == tier1FSHost && len(mounts) > 0 {
		return errors.New("-mount needs a box file system: with -tier1-fs host the agent already sees the host's files its user may read")
	}
	for _, kv := range envs {
		k, _, ok := strings.Cut(kv, "=")
		if !ok {
			return fmt.Errorf("-env %q: want NAME=value", kv)
		}
		if keyLikeName.MatchString(k) {
			return fmt.Errorf("-env %s: looks like a secret; put real keys in Ovara's environment (proxy.json credentials), never in the box", k)
		}
	}
	project, err := filepath.Abs(project)
	if err != nil {
		return err
	}
	if *dir == "" {
		*dir = defaultBoxDir()
	}
	if *tier == 1 {
		if err := checkMountsFor(mounts, *dir, tier1DstRefused); err != nil {
			return err
		}
	}
	if *tier == 2 {
		if err := checkMounts(mounts, *dir); err != nil {
			return err
		}
		if err := ensureImage(*image); err != nil {
			return err
		}
	}
	if _, err := os.Stat(filepath.Join(*dir, "config.json")); err != nil {
		fmt.Fprintf(os.Stderr, "==> first run: ovara init %s\n", *dir)
		if err := cmdInit([]string{*dir}); err != nil {
			return err
		}
	}
	if err := os.Chmod(*dir, 0o700); err != nil {
		return err
	}
	cfg, err := config.Load(filepath.Join(*dir, "proxy.json"))
	if err != nil {
		return fmt.Errorf("%s/proxy.json: %w", *dir, err)
	}
	uid, gid := boxContainerUID, boxContainerUID
	if *tier == 1 {
		if uid, gid, err = ensureUser(*agentUser); err != nil {
			return err
		}
	}

	// the run directory: traversable, not listable; work and home owned by the agent
	runID := time.Now().UTC().Format("20060102-150405")
	runDir := filepath.Join(boxRunsRoot, runID)
	if err := os.MkdirAll(boxRunsRoot, 0o711); err != nil {
		return err
	}
	if err := os.Mkdir(runDir, 0o711); err != nil {
		return err
	}
	home := filepath.Join(runDir, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "==> copying %s into the workspace (history kept, secrets left out)\n", project)
	ws, err := workspace.Create(project, filepath.Join(runDir, "work"), workspace.Options{ExtraExcludes: excludes})
	if err != nil {
		return err
	}
	for _, p := range ws.Excluded {
		fmt.Fprintf(os.Stderr, "    left out: %s\n", termSafe(p))
	}
	for _, p := range slices.Sorted(maps.Keys(ws.SecretContent)) {
		fmt.Fprintf(os.Stderr, "    left out (looks like a secret: %s): %s\n", ws.SecretContent[p], termSafe(p))
	}
	if ws.GitConfigScrubbed {
		fmt.Fprintln(os.Stderr, "    credentials taken out of URLs in the copy's .git/config")
	}
	if err := chownAll(ws.Dir, uid, gid); err != nil {
		return err
	}
	if err := os.Chown(home, uid, gid); err != nil {
		return err
	}
	// strict installs: what the project has pinned goes through; anything
	// else the agent adds pauses once (the proxy's package gate)
	pinnedFile := ""
	if *profile == boxProfileStrict {
		pins, files := strictPins(ws.Dir, *untrustedLockfiles)
		pinnedFile = filepath.Join(runDir, "pinned-packages.txt")
		if err := os.WriteFile(pinnedFile, []byte(lockfiles.FormatPins(pins)), 0o600); err != nil {
			return err
		}
		withDigest := 0
		for _, d := range pins {
			if len(d) > 0 {
				withDigest++
			}
		}
		switch {
		case *untrustedLockfiles:
			fmt.Fprintln(os.Stderr, "==> strict installs: -untrusted-lockfiles: the project's lockfiles pin nothing, so every package the agent installs pauses once")
		case len(files) == 0:
			fmt.Fprintln(os.Stderr, "==> strict installs: no lockfile in the project, so every package the agent installs pauses once")
		default:
			fmt.Fprintf(os.Stderr, "==> strict installs: %d pinned package(s) from %s go through (%d checked against the lockfile's digest); any other package pauses once\n", len(pins), strings.Join(files, ", "), withDigest)
		}
		if b, err := os.ReadFile(filepath.Join(*dir, "policy.json")); err == nil && !strings.Contains(string(b), `"package.install"`) {
			fmt.Fprintln(os.Stderr, "    warning: policy.json has no package.install rule; without one a new package is refused, not paused (add {\"action_type\": \"package.install\", \"resource\": \"*\", \"escalate\": true})")
		}
		// install scripts are the package manager's to stop; -env can turn them back on
		envs = append(multiFlag{"npm_config_ignore_scripts=true"}, envs...)
	}
	envs = append(multiFlag{"OVARA_BOX_PROFILE=" + *profile}, envs...)

	// the PUBLIC certificate, where the agent can read it (the deployment dir is 0700)
	caPub := filepath.Join(runDir, "ovara-ca.pem")
	if b, err := os.ReadFile(inDir(*dir, cfg.CACertFile)); err == nil {
		_ = os.WriteFile(caPub, b, 0o644) //nolint:gosec // the PUBLIC certificate: the agent must be able to read it
	}
	outcome := outcomeFailed
	defer func() {
		if *keep || *noCommitBack || outcome != outcomeClean {
			fmt.Fprintf(os.Stderr, "==> workspace kept at %s\n", ws.Dir)
			return
		}
		os.RemoveAll(runDir)
		os.Remove(workspace.MetaFile(ws.Dir))
	}()

	// 3. Ovara itself (tier 1: with the netns boundary; tier 2: on loopback,
	// the box reaches it through a socket)
	self, err := os.Executable()
	if err != nil {
		return err
	}
	runArgs := []string{"run", "-dir", *dir, "-ui", *uiAddr}
	if *tier == 1 {
		runArgs = append(runArgs, "--boundary", "netns", "--boundary-name", *name)
	}
	if pinnedFile != "" {
		runArgs = append(runArgs, "-package-gate", pinnedFile)
	}
	run := exec.Command(self, runArgs...) //nolint:gosec // the launcher re-executes itself with flags it validated
	run.Stdout = os.Stderr
	run.Stderr = os.Stderr
	run.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := run.Start(); err != nil {
		return err
	}
	stopRun := func() {
		_ = run.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _ = run.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = run.Process.Kill()
		}
	}
	defer stopRun()
	_, port, _ := net.SplitHostPort(cfg.ListenAddr)
	if err := waitPort("127.0.0.1:"+port, 60*time.Second, run); err != nil {
		return fmt.Errorf("ovara run did not come up: %w", err)
	}
	// the certificate is created by the first `ovara run`; copy it now if it was not there before
	if _, err := os.Stat(caPub); err != nil {
		if b, err := os.ReadFile(inDir(*dir, cfg.CACertFile)); err == nil {
			_ = os.WriteFile(caPub, b, 0o644) //nolint:gosec // the PUBLIC certificate: the agent must be able to read it
		}
	}
	receiptsBefore := countLines(inDir(*dir, cfg.ReceiptsFile))

	// 4. the agent, inside
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigs)
	gw := gateway.New(cfg.GatewayURL, cfg.GatewayToken, cfg.Environment)
	gate := newCommandGate(gw, *dir, time.Duration(cfg.EscalateTimeoutSec)*time.Second, !*noGate, agentCmd)
	a := &boxAgent{
		dir: *dir, cfg: cfg, ws: ws, runID: runID, runDir: runDir, home: home, caPub: caPub, port: port,
		envs: envs, cmd: agentCmd, gate: gate, noGate: *noGate, sigs: sigs,
		user: *agentUser, uid: uid, gid: gid, name: *name, tier1FS: *tier1FS, image: *image, mounts: mounts, pids: *pids, memory: *memory, cpus: *cpus, selfPath: self,
	}
	var exitCode int
	if *tier == 2 {
		exitCode, err = runTier2(a)
	} else {
		exitCode, err = runTier1(a)
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "==> agent exited with status %d\n", exitCode)
	printBoxSummary(inDir(*dir, cfg.ReceiptsFile), receiptsBefore)
	gate.summary()

	// 5. what comes back
	if *noCommitBack {
		outcome = outcomeKept
		return nil
	}
	// The workspace's files are read once, into a tree only Ovara can
	// write. Policy, the diff the person reads and the commit that lands
	// all come from that tree, so nothing the agent (or a process it left
	// behind) changes after this point can come back.
	snap, err := ws.Snapshot()
	if err != nil {
		return err
	}
	if len(snap.Changes) == 0 {
		fmt.Fprintln(os.Stderr, "==> the agent changed nothing")
		outcome = outcomeClean
		return nil
	}
	branch := "ovara/box-" + runID
	ctx := context.Background()
	plan, err := planCommitBack(snap.Changes, func(path, status string) (string, error) {
		d, err := gw.CheckAction(ctx, "fs.commit_back.path", "path:"+path, map[string]string{"status": status})
		if err != nil {
			return "", fmt.Errorf("gateway: %w", err)
		}
		return d.Decision, nil
	}, *allowBinary)
	if err != nil {
		return err
	}
	for _, p := range plan.policy {
		fmt.Fprintf(os.Stderr, "    policy keeps out: %s\n", termSafe(p))
	}
	for _, p := range plan.binary {
		fmt.Fprintf(os.Stderr, "    kept out (binary file, cannot be reviewed; -allow-binary brings it back): %s\n", termSafe(p))
	}
	for _, p := range plan.flagged {
		fmt.Fprintf(os.Stderr, "    ⚠ sensitive file changed: %s\n", termSafe(p))
	}
	if len(plan.allowed) == 0 {
		fmt.Fprintln(os.Stderr, "==> every changed path is kept out; nothing comes back")
		outcome = outcomeKept
		return nil
	}
	if snap, err = ws.Without(snap, plan.revert); err != nil {
		return err
	}
	if len(snap.Changes) != len(plan.allowed) {
		return fmt.Errorf("internal: %d path(s) left to bring back, %d expected; nothing comes back", len(snap.Changes), len(plan.allowed))
	}
	rev, err := ws.Review(snap, boxPreviewMax)
	if err != nil {
		return err
	}
	// the whole diff, for when the approval shows only part of it
	fullDiff := filepath.Join(runDir, "commit-back.diff")
	if err := os.WriteFile(fullDiff, []byte(rev.Stat+"\n"+rev.Full), 0o600); err != nil {
		return err
	}
	if rev.Truncated() {
		fmt.Fprintf(os.Stderr, "    ⚠ the diff is too long to show in full: %d of %d bytes are not in the approval; read all of it in %s\n", rev.TotalBytes-rev.ShownBytes, rev.TotalBytes, fullDiff)
	}
	ctxLines := commitBackContext(plan, snap, rev, branch, fullDiff)
	resource := fmt.Sprintf("commit:%s (%d files, tree %s)", filepath.Base(ws.Project), len(plan.allowed), snap.Tree[:12])
	d, err := gw.CheckAction(ctx, "fs.commit_back", resource, ctxLines)
	if err != nil {
		return fmt.Errorf("gateway: %w", err)
	}
	switch d.Decision {
	case decisionDeny:
		fmt.Fprintln(os.Stderr, "==> policy refuses the commit-back; the workspace is kept")
		outcome = outcomeKept
		return nil
	case decisionEscalate:
		id, err := gw.CreateApprovalFor(ctx, d, "fs.commit_back", resource)
		if err != nil {
			return fmt.Errorf("gateway: %w", err)
		}
		fmt.Fprintf(os.Stderr, "==> waiting for you to approve the changes (%d files, approval %s): the approval page or `ovara approvals -dir %s`\n", len(plan.allowed), id, *dir)
		status, err := waitApproval(ctx, gw, id, capToApprovalTTL(*dir, *approveTimeout))
		if err != nil {
			return err
		}
		if status != approvalApproved {
			fmt.Fprintf(os.Stderr, "==> %s; nothing comes back, the workspace is kept\n", status)
			outcome = outcomeKept
			return nil
		}
	}
	// exactly the reviewed tree, or nothing
	commit, err := ws.CommitTree(branch, snap)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "==> changes are on branch %s of %s (%s); review and merge it like a pull request\n", branch, ws.Project, commit[:12])
	outcome = outcomeClean
	if exitCode != 0 {
		return fmt.Errorf("agent exited with status %d", exitCode)
	}
	return nil
}

// strictPins are the packages a strict box lets through without a question,
// with their lockfile digests, and the lockfiles read. A project whose
// lockfiles are not trusted pins nothing.
func strictPins(workspace string, untrusted bool) (map[string][]string, []string) {
	pins, files := lockfiles.ScanPins(workspace)
	if untrusted {
		return map[string][]string{}, files
	}
	return pins, files
}

// agentVars is Ovara's agent environment for a proxy at host, with the CA
// path rewritten to where the box sees the public certificate.
func agentVars(a *boxAgent, host, caPath string) ([]string, error) {
	vars, _, err := agentEnv(a.dir, a.cfg, host)
	if err != nil {
		return nil, err
	}
	caIn := inDir(a.dir, a.cfg.CACertFile)
	out := make([]string, 0, len(vars))
	for _, v := range vars {
		val := v.value
		if val == caIn {
			val = caPath
		}
		out = append(out, v.name+"="+val)
	}
	return out, nil
}

// mergeEnv returns base with each NAME=value of over replacing the same
// name (so -env PATH=... wins instead of standing second in line).
func mergeEnv(base, over []string) []string {
	idx := map[string]int{}
	out := append([]string(nil), base...)
	for i, kv := range out {
		k, _, _ := strings.Cut(kv, "=")
		idx[k] = i
	}
	for _, kv := range over {
		k, _, _ := strings.Cut(kv, "=")
		if i, ok := idx[k]; ok {
			out[i] = kv
			continue
		}
		idx[k] = len(out)
		out = append(out, kv)
	}
	return out
}

// tier1Spec is what box-init -tier1 needs for a's agent (env holds the
// proxy token: it travels on a pipe, never on a command line).
func (a *boxAgent) tier1Spec(env []string) (tier1Spec, error) {
	spec := tier1Spec{Netns: a.name, UID: a.uid, GID: a.gid, Env: env, Argv: a.cmd, Dir: a.ws.Dir}
	if a.tier1FS == tier1FSHost {
		return spec, nil
	}
	spec.Root = filepath.Join(a.runDir, "root")
	if err := os.Mkdir(spec.Root, 0o700); err != nil {
		return spec, err
	}
	spec.Binds = []tier1Bind{{Src: a.ws.Dir, Dst: a.ws.Dir, RW: true}, {Src: a.home, Dst: a.home, RW: true}}
	if _, err := os.Stat(a.caPub); err == nil {
		spec.Binds = append(spec.Binds, tier1Bind{Src: a.caPub, Dst: a.caPub})
	}
	for _, m := range a.mounts {
		src, dst, _ := strings.Cut(m, ":")
		abs, err := filepath.Abs(src)
		if err != nil {
			return spec, err
		}
		if abs, err = filepath.EvalSymlinks(abs); err != nil {
			return spec, err
		}
		spec.Binds = append(spec.Binds, tier1Bind{Src: abs, Dst: filepath.Clean(dst)})
	}
	return spec, nil
}

// runTier1: the agent as an unprivileged host user inside the network
// namespace and (unless -tier1-fs host) a root file system of its own,
// traced from this process.
func runTier1(a *boxAgent) (int, error) {
	proxyIP := boundaryProxyIP(boundarySubnetIdx(a.name))
	vars, err := agentVars(a, proxyIP, a.caPub)
	if err != nil {
		return 0, err
	}
	env := []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin",
		"HOME=" + a.home, "USER=" + a.user, "LOGNAME=" + a.user,
		"TERM=" + envOr("TERM", "xterm"), "LANG=" + envOr("LANG", "C.UTF-8"),
		"NO_PROXY=127.0.0.1,localhost", "no_proxy=127.0.0.1,localhost",
		"OVARA_BOX=1", "OVARA_BOX_TIER=1", "OVARA_WORKSPACE=" + a.ws.Dir,
	}
	env = mergeEnv(append(env, vars...), a.envs)
	spec, err := a.tier1Spec(env)
	if err != nil {
		return 0, err
	}
	agent, specDone, err := tier1Command(a.selfPath, spec)
	if err != nil {
		return 0, err
	}
	defer specDone()
	agent.Stdin, agent.Stdout, agent.Stderr = os.Stdin, os.Stdout, os.Stderr
	fmt.Fprintf(os.Stderr, "==> tier 1: running as %s in %s (network only through Ovara at %s:%s)\n", a.user, a.ws.Dir, proxyIP, a.port)
	if a.tier1FS == tier1FSHost {
		fmt.Fprintf(os.Stderr, "==> -tier1-fs host: the agent sees the host's file system: %s can read any host file it has permission to (including %s). Unsafe on a machine with secrets.\n", a.user, a.ws.Project)
	} else {
		fmt.Fprintln(os.Stderr, "==> tier 1 file system: the host's system directories read-only, the workspace, a fresh home and /tmp; nothing else of the host")
	}
	if a.noGate {
		if err := agent.Start(); err != nil {
			return 0, fmt.Errorf("starting the agent: %w", err)
		}
		agentDone := make(chan error, 1)
		go func() { agentDone <- agent.Wait() }()
		var agentErr error
		select {
		case agentErr = <-agentDone:
		case s := <-a.sigs:
			fmt.Fprintf(os.Stderr, "\n==> %s: stopping the agent\n", s)
			_ = syscall.Kill(-agent.Process.Pid, syscall.SIGTERM)
			select {
			case agentErr = <-agentDone:
			case <-time.After(10 * time.Second):
				_ = syscall.Kill(-agent.Process.Pid, syscall.SIGKILL)
				agentErr = <-agentDone
			}
		}
		if agentErr != nil {
			var ee *exec.ExitError
			if errors.As(agentErr, &ee) {
				return ee.ExitCode(), nil
			}
			return 0, agentErr
		}
		return 0, nil
	}
	// the gate traces the tree from the launcher's own process; a signal
	// to us is forwarded to the agent's process group
	tr := &boxgate.Tracer{Decide: a.gate.decide, Skip: a.gate.skip}
	type res struct {
		code int
		err  error
	}
	done := make(chan res, 1)
	go func() {
		c, err := tr.Run(agent)
		done <- res{c, err}
	}()
	var r res
	select {
	case r = <-done:
	case s := <-a.sigs:
		fmt.Fprintf(os.Stderr, "\n==> %s: stopping the agent\n", s)
		for agent.Process == nil {
			time.Sleep(50 * time.Millisecond)
		}
		_ = syscall.Kill(-agent.Process.Pid, syscall.SIGTERM)
		select {
		case r = <-done:
		case <-time.After(10 * time.Second):
			_ = syscall.Kill(-agent.Process.Pid, syscall.SIGKILL)
			r = <-done
		}
	}
	if r.err != nil {
		return 0, fmt.Errorf("running the agent under the command gate: %w", r.err)
	}
	return r.code, nil
}

// runTier2: the agent in a container. The container has loopback only;
// box-init (PID 1) relays 127.0.0.1:<port> to the proxy socket and asks the
// gate socket about every exec. Both sockets live in a root-only directory.
func runTier2(a *boxAgent) (int, error) {
	sockDir := filepath.Join(a.runDir, "sock")
	if err := os.Mkdir(sockDir, 0o700); err != nil {
		return 0, err
	}
	pl, err := net.Listen("unix", filepath.Join(sockDir, boxProxySock))
	if err != nil {
		return 0, err
	}
	defer pl.Close()
	go relayTo(pl, func() (net.Conn, error) { return net.Dial("tcp", "127.0.0.1:"+a.port) })
	if !a.noGate {
		gl, err := net.Listen("unix", filepath.Join(sockDir, boxGateSock))
		if err != nil {
			return 0, err
		}
		defer gl.Close()
		go serveGate(gl, a.gate)
	}

	vars, err := agentVars(a, "127.0.0.1", boxInCA)
	if err != nil {
		return 0, err
	}
	env := []string{
		"HOME=" + boxInHome, "USER=" + boxDefaultUser, "LOGNAME=" + boxDefaultUser,
		"TERM=" + envOr("TERM", "xterm"), "LANG=" + envOr("LANG", "C.UTF-8"),
		"NO_PROXY=127.0.0.1,localhost", "no_proxy=127.0.0.1,localhost",
		"OVARA_BOX=1", "OVARA_BOX_TIER=2", "OVARA_WORKSPACE=" + boxInWork,
	}
	env = mergeEnv(append(env, vars...), a.envs)
	// the agent token is in there: a root-only file, not the docker command line
	envFile := filepath.Join(a.runDir, "agent.env")
	if err := os.WriteFile(envFile, []byte(strings.Join(env, "\n")+"\n"), 0o600); err != nil {
		return 0, err
	}
	cname := boxContainerName + a.runID
	args := []string{
		"run", "--rm", "-i", "--name", cname, "--label", "ovara.box=" + a.runID,
		"--network", "none",
		"--cap-drop", "ALL", "--cap-add", "SETUID", "--cap-add", "SETGID", "--cap-add", "KILL",
		"--security-opt", "no-new-privileges",
		"--read-only",
		"--tmpfs", "/tmp:rw,nosuid,nodev,exec,size=4g,mode=1777",
		"--tmpfs", "/scratch:rw,nosuid,nodev,exec,size=8g,mode=0755,uid=" + strconv.Itoa(boxContainerUID) + ",gid=" + strconv.Itoa(boxContainerUID),
		"--ipc", "private",
		"--hostname", "ovara-box",
		"--pids-limit", strconv.Itoa(a.pids),
		"-v", a.ws.Dir + ":" + boxInWork,
		"-v", a.home + ":" + boxInHome,
		"-v", sockDir + ":" + boxSockDir + ":ro",
		"-v", a.selfPath + ":" + boxInBinary + ":ro",
		"-v", a.caPub + ":" + boxInCA + ":ro",
		"--env-file", envFile,
		"-w", boxInWork,
		"--user", "0:0",
		"--entrypoint", boxInBinary,
	}
	if a.memory != "" {
		args = append(args, "--memory", a.memory)
	}
	if a.cpus != "" {
		args = append(args, "--cpus", a.cpus)
	}
	for _, m := range a.mounts {
		src, dst, _ := strings.Cut(m, ":")
		abs, _ := filepath.Abs(src)
		args = append(args, "-v", abs+":"+dst+":ro")
	}
	if isTerminal(os.Stdin) {
		args = append(args, "-t")
	}
	args = append(args, a.image, "box-init",
		"-uid", strconv.Itoa(boxContainerUID), "-gid", strconv.Itoa(boxContainerUID),
		"-proxy", "127.0.0.1:"+a.port, "-gate="+strconv.FormatBool(!a.noGate), "--")
	args = append(args, a.cmd...)
	agent := exec.Command("docker", args...) //nolint:gosec // flags built here; the agent command is what the person asked to run
	agent.Stdin, agent.Stdout, agent.Stderr = os.Stdin, os.Stdout, os.Stderr
	agent.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	fmt.Fprintf(os.Stderr, "==> tier 2: container %s from %s (no network but Ovara, no capabilities, read-only root; /work is the workspace)\n", cname, a.image)
	if err := agent.Start(); err != nil {
		return 0, fmt.Errorf("docker run: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- agent.Wait() }()
	var werr error
	select {
	case werr = <-done:
	case s := <-a.sigs:
		fmt.Fprintf(os.Stderr, "\n==> %s: stopping the agent\n", s)
		_ = exec.Command("docker", "kill", "--signal", "TERM", cname).Run() //nolint:gosec // our own container name
		select {
		case werr = <-done:
		case <-time.After(10 * time.Second):
			_ = exec.Command("docker", "kill", cname).Run() //nolint:gosec // our own container name
			werr = <-done
		}
	}
	// never leave the box behind
	_ = exec.Command("docker", "rm", "-f", cname).Run() //nolint:gosec // our own container name
	if werr == nil {
		return 0, nil
	}
	var ee *exec.ExitError
	if !errors.As(werr, &ee) {
		return 0, werr
	}
	if ee.ExitCode() == 125 {
		return 0, errors.New("docker could not start the box (exit 125; see the message above)")
	}
	return ee.ExitCode(), nil
}

// serveGate answers the box's command gate: the first connection only (the
// box's PID 1), one decision per line, until it closes.
func serveGate(ln net.Listener, gate *commandGate) {
	c, err := ln.Accept()
	ln.Close()
	if err != nil {
		return
	}
	defer c.Close()
	dec := json.NewDecoder(c)
	enc := json.NewEncoder(c)
	for {
		var req gateRequest
		if err := dec.Decode(&req); err != nil {
			return
		}
		v := gate.decide(boxgate.Exec{Exe: req.Exe, Argv: req.Argv, Cwd: req.Cwd})
		if err := enc.Encode(gateReply{Allow: v == boxgate.Allow}); err != nil {
			return
		}
	}
}

// ensureImage makes sure the box image is there, pulling it when it names a
// registry.
func ensureImage(image string) error {
	if _, err := exec.LookPath("docker"); err != nil {
		return errors.New("-tier 2 needs Docker (the docker command and a running daemon)")
	}
	if exec.Command("docker", "image", "inspect", image).Run() == nil { //nolint:gosec // an image name, passed as one argument
		return nil
	}
	if strings.Contains(image, "/") {
		pull := exec.Command("docker", "pull", image) //nolint:gosec // an image name, passed as one argument
		pull.Stdout, pull.Stderr = os.Stderr, os.Stderr
		if pull.Run() == nil {
			return nil
		}
	}
	return fmt.Errorf("box image %q not found: build it with `docker build -t %s box/` from the Ovara repository (and extend it with your agent), or pass -image", image, image)
}

// secret locations that are never mounted into a box, nor any directory
// that contains one (so neither ~ nor /home)
var secretMountPaths = []string{
	".ssh", ".aws", ".gnupg", ".config/gh", ".config/gcloud", ".azure", ".docker", ".kube",
	".netrc", ".npmrc", ".pypirc", ".git-credentials", ".ovara",
}

func checkMounts(mounts []string, ovaraDir string) error {
	return checkMountsFor(mounts, ovaraDir, []string{boxInWork, boxInHome, boxSockDir, filepath.Dir(boxInBinary), filepath.Dir(boxInCA), "/tmp", "/scratch", "/proc", "/sys", "/dev"})
}

// checkMountsFor checks -mount SRC:DST pairs: no secret or system path as
// SRC, and no DST on, in or above one of the box's own (ownDst; a place
// inside /tmp or /scratch is fine).
func checkMountsFor(mounts []string, ovaraDir string, ownDst []string) error {
	inside := func(p, dir string) bool { return strings.HasPrefix(p, strings.TrimSuffix(dir, "/")+"/") }
	// never mounted, nor anything inside them
	closed := []string{"/root", "/etc", "/proc", "/sys", "/dev", "/boot", "/run", "/var/run", "/var/lib/docker", "/var/lib/ovara"}
	if abs, err := filepath.Abs(ovaraDir); err == nil {
		closed = append(closed, abs)
	}
	homes := []string{"/root"}
	if entries, err := os.ReadDir("/home"); err == nil {
		for _, e := range entries {
			homes = append(homes, filepath.Join("/home", e.Name()))
		}
	}
	for _, h := range homes {
		for _, s := range secretMountPaths {
			closed = append(closed, filepath.Join(h, s))
		}
	}
	for _, m := range mounts {
		src, dst, ok := strings.Cut(m, ":")
		if !ok || src == "" || !strings.HasPrefix(dst, "/") || strings.Contains(dst, ":") {
			return fmt.Errorf("-mount %q: want SRC:/absolute/destination", m)
		}
		abs, err := filepath.Abs(src)
		if err != nil {
			return err
		}
		if abs, err = filepath.EvalSymlinks(abs); err != nil {
			return fmt.Errorf("-mount %s: %w", src, err)
		}
		if abs == "/" {
			return fmt.Errorf("-mount %s: refused (the whole host)", src)
		}
		for _, c := range closed {
			if abs == c || inside(abs, c) {
				return fmt.Errorf("-mount %s: refused (inside %s; secrets and system paths never go into a box)", src, c)
			}
		}
		for _, c := range append(append([]string(nil), closed...), homes...) {
			if inside(c, abs) || (abs == c) {
				return fmt.Errorf("-mount %s: refused (it contains %s; secrets and system paths never go into a box)", src, c)
			}
		}
		d := filepath.Clean(dst)
		for _, o := range ownDst {
			if (o == "/tmp" || o == "/scratch") && inside(d, o) {
				continue // a file or directory inside the box's own scratch space is fine
			}
			if d == o || inside(d, o) || inside(o, d) {
				return fmt.Errorf("-mount %s: destination %s clashes with the box's own %s", src, dst, o)
			}
		}
	}
	return nil
}

func isTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}

// commandGate decides each exec in the box through the gateway.
type commandGate struct {
	gw      *gateway.Client
	dir     string
	timeout time.Duration
	on      bool
	started bool // the agent itself has been exec'd; before that, our wrappers run
	mu      sync.Mutex
	counts  map[string]int
	// launch is the agent command the person gave; launched is set once
	// the first checked exec has been compared with it
	launch   []string
	launched bool
}

func newCommandGate(gw *gateway.Client, dir string, timeout time.Duration, on bool, launch []string) *commandGate {
	return &commandGate{gw: gw, dir: dir, timeout: timeout, on: on, counts: map[string]int{}, launch: launch}
}

// skip exempts the launcher's own box-init -tier1, the first program in
// the tree; what it execs next is the agent.
func (g *commandGate) skip(e boxgate.Exec) bool {
	if g.started {
		return false
	}
	g.started = true
	return len(e.Argv) >= 3 && e.Argv[1] == "box-init" && e.Argv[2] == "-tier1"
}

func (g *commandGate) decide(e boxgate.Exec) boxgate.Verdict {
	// Policy matches one canonical spelling of the command (PolicyLine);
	// the person sees the command as it was actually run.
	raw := boxgate.CommandLine(e)
	line := boxgate.PolicyLine(e)
	preview := map[string]string{"command": raw, "program": e.Exe, "directory": e.Cwd}
	d, err := g.gw.CheckAction(context.Background(), "shell", "shell:"+line, preview)
	shown := termSafe(raw) // what is printed; policy and approvals get the real bytes
	launch := g.isLaunch(e)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ovara] command gate: gateway unreachable, refusing: %s (%v)\n", shown, err)
		g.count(countDenied)
		return boxgate.Deny
	}
	switch d.Decision {
	case decisionAllow:
		g.count(countAllowed)
		return boxgate.Allow
	case decisionDeny:
		fmt.Fprintf(os.Stderr, "[ovara] command refused by policy: %s\n", shown)
		g.count(countDenied)
		return boxgate.Deny
	}
	if launch {
		// the person typed this command to start the box; asking them to
		// approve it (say, an agent started with its own checks off)
		// would be asking them what they just said
		g.count(countAllowed)
		return boxgate.Allow
	}
	id, err := g.gw.CreateApprovalFor(context.Background(), d, "shell", "shell:"+line)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ovara] command gate: could not open an approval, refusing: %s (%v)\n", shown, err)
		g.count(countDenied)
		return boxgate.Deny
	}
	fmt.Fprintf(os.Stderr, "[ovara] command paused for your approval (%s): %s\n", id, shown)
	status, err := waitApproval(context.Background(), g.gw, id, g.timeout)
	if err != nil || status != approvalApproved {
		if status == "" {
			status = approvalError
		}
		fmt.Fprintf(os.Stderr, "[ovara] command %s: %s\n", status, shown)
		g.count(countDenied)
		return boxgate.Deny
	}
	g.count(countApproved)
	return boxgate.Allow
}

// isLaunch reports whether e is the agent command `ovara box` was given,
// exactly as given, the first time it is seen. Later execs, however
// similar, are the agent's own.
func (g *commandGate) isLaunch(e boxgate.Exec) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.launched || len(g.launch) == 0 {
		return false
	}
	g.launched = true
	if len(e.Argv) != len(g.launch) {
		return false
	}
	for i, a := range e.Argv {
		if a != g.launch[i] {
			return false
		}
	}
	return true
}

func (g *commandGate) count(k string) {
	g.mu.Lock()
	g.counts[k]++
	g.mu.Unlock()
}

func (g *commandGate) summary() {
	if !g.on {
		fmt.Fprintln(os.Stderr, "==> command gate off (-no-command-gate)")
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	fmt.Fprintf(os.Stderr, "==> %d command(s) checked: %d allowed, %d approved by you, %d refused\n",
		g.counts[countAllowed]+g.counts[countApproved]+g.counts[countDenied], g.counts[countAllowed], g.counts[countApproved], g.counts[countDenied])
}

func waitApproval(ctx context.Context, gw *gateway.Client, id string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		st, err := gw.ApprovalStatus(ctx, id)
		if err != nil {
			return "", fmt.Errorf("gateway: %w", err)
		}
		if st != "pending" {
			return st, nil
		}
		time.Sleep(2 * time.Second)
	}
	return "timed out", nil
}

// printBoxSummary tallies the receipts this run added.
func printBoxSummary(receipts string, skip int) {
	f, err := os.Open(receipts)
	if err != nil {
		return
	}
	defer f.Close()
	counts := map[string]int{}
	hosts := map[string]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	n := 0
	for sc.Scan() {
		n++
		if n <= skip {
			continue
		}
		line := sc.Text()
		dec := jsonField(line, "decision")
		counts[dec]++
		if u := jsonField(line, "url"); u != "" {
			h := u
			if i := strings.Index(h, "://"); i >= 0 {
				h = h[i+3:]
			}
			if i := strings.IndexAny(h, "/?"); i >= 0 {
				h = h[:i]
			}
			hosts[h] = true
		}
	}
	fmt.Fprintf(os.Stderr, "==> %d request(s) through Ovara: %d allowed, %d paused, %d denied; %d host(s)\n",
		n-skip, counts[decisionAllow], counts[decisionEscalate], counts[decisionDeny], len(hosts))
}

func jsonField(line, key string) string {
	i := strings.Index(line, `"`+key+`":"`)
	if i < 0 {
		return ""
	}
	rest := line[i+len(key)+4:]
	if j := strings.IndexByte(rest, '"'); j >= 0 {
		return rest[:j]
	}
	return ""
}

func countLines(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	return strings.Count(string(b), "\n")
}

func waitPort(addr string, timeout time.Duration, proc *exec.Cmd) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
			c.Close()
			return nil
		}
		if proc.ProcessState != nil && proc.ProcessState.Exited() {
			return errors.New("exited")
		}
		time.Sleep(250 * time.Millisecond)
	}
	return errors.New("timeout")
}

func ensureUser(name string) (uid, gid int, err error) {
	u, err := user.Lookup(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "==> creating system user %s for the agent\n", name)
		cmd := exec.Command("useradd", "--system", "--no-create-home", "--shell", "/bin/bash", name)
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return 0, 0, fmt.Errorf("useradd %s: %w", name, err)
		}
		if u, err = user.Lookup(name); err != nil {
			return 0, 0, err
		}
	}
	if u.Uid == "0" {
		return 0, 0, errors.New("the agent user must not be root")
	}
	uid, _ = strconv.Atoi(u.Uid)
	gid, _ = strconv.Atoi(u.Gid)
	return uid, gid, nil
}

func chownAll(root string, uid, gid int) error {
	return filepath.Walk(root, func(p string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, uid, gid)
	})
}

func defaultBoxDir() string {
	home := os.Getenv("HOME")
	if su := os.Getenv("SUDO_USER"); su != "" {
		if u, err := user.Lookup(su); err == nil {
			home = u.HomeDir
		}
	}
	if home == "" {
		home = "/root"
	}
	return filepath.Join(home, ".ovara", "box")
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// capToApprovalTTL keeps a wait within the time the gateway keeps an
// approval open (approval_pending_ttl_secs in config.json, default 10
// minutes): waiting longer only ends in "expired", after a person may
// already have read the diff and clicked approve.
func capToApprovalTTL(dir string, wait time.Duration) time.Duration {
	ttl := 10 * time.Minute
	if raw, err := os.ReadFile(filepath.Join(dir, "config.json")); err == nil {
		var c struct {
			TTL int `json:"approval_pending_ttl_secs"`
		}
		if json.Unmarshal(raw, &c) == nil {
			switch {
			case c.TTL > 0:
				ttl = time.Duration(c.TTL) * time.Second
			case c.TTL < 0:
				return wait // expiry is off
			}
		}
	}
	if wait > ttl {
		fmt.Fprintf(os.Stderr, "==> -approve-timeout %s is longer than the gateway keeps an approval open (%s); waiting %s (raise approval_pending_ttl_secs in config.json to wait longer)\n", wait, ttl, ttl)
		return ttl
	}
	return wait
}
