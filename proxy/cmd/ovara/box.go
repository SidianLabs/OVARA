//go:build linux || darwin

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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"ovara.proxy/internal/boxgate"
	"ovara.proxy/internal/config"
	"ovara.proxy/internal/gateway"
	"ovara.proxy/internal/lockfiles"
	"ovara.proxy/internal/sandbox"
	"ovara.proxy/internal/vm"
	"ovara.proxy/internal/workspace"
)

const (
	boxRunsRoot   = "/var/lib/ovara/runs"
	boxPreviewMax = 64 << 10

	// tier 2: the box image's agent user, and where things are inside it
	boxContainerUID  = 10001
	boxInWork        = "/work"
	boxInHome        = "/home/agent"
	boxInCA          = "/etc/ovara/ca.pem"
	boxInBinary      = "/opt/ovara/ovara"
	boxContainerName = "ovara-box-"

	// approval states (the gateway's decisions are in commitback.go)
	approvalApproved = "approved"
	approvalError    = "error"

	// command-gate tallies
	countAllowed  = "allowed"
	countPaused   = "paused"
	countApproved = "approved"
	countDenied   = "denied"
)

// tier1DstRefused lists where a -mount may not land in a tier 1 box: the
// box's own system, devices and run directory.
var tier1DstRefused = []string{"/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/etc", "/dev", "/proc", "/sys", "/run", "/tmp", "/var/tmp", boxRunsRoot}

// boxAgent is what both tiers need to start the agent.
type boxAgent struct {
	dir          string
	cfg          *config.Config
	ws           *workspace.Workspace
	runID        string
	runDir       string
	home         string
	caPub        string
	port         string
	envs         []string
	cmd          []string
	gate         *commandGate
	noGate       bool
	sigs         chan os.Signal
	user         string   // tier 1
	uid, gid     int      // tier 1: the agent user's
	name         string   // tier 1: netns name
	tier1FS      string   // tier 1: isolated or host
	visibleProcs bool     // tier 1 isolated: accept a /proc that shows the host's processes
	image        string   // tier 2
	mounts       []string // SRC:DST, read-only (tier 1 isolated, tier 2)
	pids         int      // tier 2
	memory       string   // tier 2
	cpus         string   // tier 2
	selfPath     string
	// the seccomp opt-outs, every tier
	allowUserNS    bool
	allowDebuggers bool
}

func cmdBox(args []string) (err error) {
	o, x, err := parseBoxArgs(args)
	if err != nil {
		return err
	}
	if x.printManifest {
		return printManifest(o)
	}
	// macOS has no tier 1 or 2: there the box always runs in a Linux VM
	if x.vm == "" && runtime.GOOS == "darwin" {
		x.vm = "lima"
	}
	var drv vm.Driver
	var vmBin string // the Linux ovara the guest runs
	if x.vm != "" {
		if drv, err = vmDriver(x.vm); err != nil {
			return err
		}
		if len(o.mounts) > 0 {
			return errors.New("-mount is not available with -vm yet")
		}
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		if vmBin, err = guestBinary(x.vmBinary, exe); err != nil {
			return err
		}
	}
	// a VM runs as the person (Lima refuses root); tiers 1 and 2 need root
	if drv == nil && os.Geteuid() != 0 {
		return errors.New("ovara box needs root (tier 1: the network namespace; tier 2: handing the workspace to the box's user and keeping Ovara's sockets out of its reach): run it with sudo; the agent itself runs as an unprivileged user")
	}
	project, err := filepath.Abs(o.project)
	if err != nil {
		return err
	}
	o.project = project
	if o.dir == "" {
		o.dir = defaultBoxDir()
	}
	if drv == nil && o.tier == 1 {
		if err := checkMountsFor(o.mounts, o.dir, tier1DstRefused); err != nil {
			return err
		}
		if err := checkTier1Tools(); err != nil {
			return err
		}
	}
	if drv == nil && o.tier == 2 {
		if err := checkMounts(o.mounts, o.dir); err != nil {
			return err
		}
		if err := ensureImage(o.image); err != nil {
			return err
		}
	}
	if _, err := os.Stat(filepath.Join(o.dir, "config.json")); err != nil {
		fmt.Fprintf(os.Stderr, "==> first run: ovara init %s\n", o.dir)
		if err := cmdInit([]string{o.dir}); err != nil {
			return err
		}
	}
	if err := os.Chmod(o.dir, 0o700); err != nil {
		return err
	}
	cfg, err := config.Load(filepath.Join(o.dir, "proxy.json"))
	if err != nil {
		return fmt.Errorf("%s/proxy.json: %w", o.dir, err)
	}
	if o.agent != "" {
		tok, err := agentProxyToken(cfg, o.agent)
		if err != nil {
			return err
		}
		cfg.AgentToken = tok
	}
	uid, gid := boxContainerUID, boxContainerUID
	if drv == nil && o.tier == 1 {
		if uid, gid, err = ensureUser(o.user); err != nil {
			return err
		}
	}

	// the run directory: traversable, not listable; work and home owned by the agent
	runID := time.Now().UTC().Format("20060102-150405")
	runStarted := time.Now()
	var receiptsBefore int // the chain's length before the run, once Ovara is up
	proxyUp, landedCommit := false, ""
	// a VM's runs live in the person's own deployment directory
	runsRoot := boxRunsRoot
	if drv != nil {
		runsRoot = filepath.Join(o.dir, "runs")
	}
	runDir := filepath.Join(runsRoot, runID)
	if err := os.MkdirAll(runsRoot, 0o711); err != nil {
		return err
	}
	if err := os.Mkdir(runDir, 0o711); err != nil {
		return err
	}
	var events *sandbox.Events
	if x.events != "" {
		if events, err = sandbox.OpenEvents(x.events, runID); err != nil {
			return err
		}
		defer events.Close()
	}
	// the run's summary: filled in as it goes, written last whatever happens
	summary := &sandbox.Summary{Outcome: sandbox.OutcomeFailed}
	defer func() {
		// The attestation comes last, after the Ovara the box started has
		// stopped (its stop is deferred later, so it runs first) and the
		// summary is final. Without a proxy nothing was recorded to attest.
		if proxyUp {
			if rel, aerr := attestBoxRun(o, cfg, runID, runStarted, receiptsBefore, landedCommit, summary); aerr != nil {
				fmt.Fprintf(os.Stderr, "==> no attestation for this run: %v\n", aerr)
			} else {
				summary.Attestation = rel
				fmt.Fprintf(os.Stderr, "==> attestation: %s (ovara attest verify -dir %s)\n", rel, o.dir)
			}
		}
		last := sandbox.Event{Event: sandbox.EventRunFinished, Summary: summary}
		if err != nil {
			last.Error = err.Error()
		}
		events.Emit(last)
	}()
	events.Emit(sandbox.Event{Event: sandbox.EventRunCreated, Manifest: o.manifest()})
	home := filepath.Join(runDir, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "==> copying %s into the workspace (history kept, secrets left out)\n", project)
	ws, err := workspace.Create(project, filepath.Join(runDir, "work"), workspace.Options{ExtraExcludes: o.excludes})
	if err != nil {
		return err
	}
	events.Emit(sandbox.Event{Event: sandbox.EventWorkspaceCopied, Workspace: ws.Dir})
	for _, p := range ws.Excluded {
		fmt.Fprintf(os.Stderr, "    left out: %s\n", termSafe(p))
	}
	for _, p := range slices.Sorted(maps.Keys(ws.SecretContent)) {
		fmt.Fprintf(os.Stderr, "    left out (looks like a secret: %s): %s\n", ws.SecretContent[p], termSafe(p))
	}
	if ws.GitConfigScrubbed {
		fmt.Fprintln(os.Stderr, "    credentials taken out of URLs in the copy's .git/config")
	}
	// the agent's user owns its copy (in a VM, box-init hands it over there)
	if drv == nil {
		if err := chownAll(ws.Dir, uid, gid); err != nil {
			return err
		}
		if err := os.Chown(home, uid, gid); err != nil {
			return err
		}
	}
	// strict installs: what the project has pinned goes through; anything
	// else the agent adds pauses once (the proxy's package gate)
	pinnedFile := ""
	unattended := o.profile == boxProfileCI // no one answers: a pause is a refusal
	if o.profile == boxProfileStrict || unattended {
		pins, files := strictPins(ws.Dir, o.untrusted)
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
		other := "pauses once"
		if unattended {
			other = "is refused (ci profile)"
		}
		switch {
		case o.untrusted:
			fmt.Fprintf(os.Stderr, "==> strict installs: -untrusted-lockfiles: the project's lockfiles pin nothing, so every package the agent installs %s\n", other)
		case len(files) == 0:
			fmt.Fprintf(os.Stderr, "==> strict installs: no lockfile in the project, so every package the agent installs %s\n", other)
		default:
			fmt.Fprintf(os.Stderr, "==> strict installs: %d pinned package(s) from %s go through (%d checked against the lockfile's digest); any other package %s\n", len(pins), strings.Join(files, ", "), withDigest, other)
		}
		if b, err := os.ReadFile(filepath.Join(o.dir, "policy.json")); err == nil && !strings.Contains(string(b), `"package.install"`) {
			fmt.Fprintln(os.Stderr, "    warning: policy.json has no package.install rule; without one a new package is refused, not paused (add {\"action_type\": \"package.install\", \"resource\": \"*\", \"escalate\": true})")
		}
		// install scripts are the package manager's to stop; -env can turn them back on
		// (Composer runs only plugins, and only ones the project allows;
		// non-interactive, an unlisted one is never allowed at a prompt)
		o.envs = append(multiFlag{"npm_config_ignore_scripts=true", "COMPOSER_NO_INTERACTION=1"}, o.envs...)
	}
	o.envs = append(multiFlag{"OVARA_BOX_PROFILE=" + o.profile}, o.envs...)

	// the PUBLIC certificate, where the agent can read it (the deployment dir is 0700)
	caPub := filepath.Join(runDir, "ovara-ca.pem")
	if b, err := os.ReadFile(inDir(o.dir, cfg.CACertFile)); err == nil {
		_ = os.WriteFile(caPub, b, 0o644) //nolint:gosec // the PUBLIC certificate: the agent must be able to read it
	}
	defer func() {
		if o.keep || o.noCommitBack || summary.Outcome != sandbox.OutcomeClean {
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
	runArgs := []string{"run", "-dir", o.dir, "-ui", o.ui, "-no-attest"} // the box attests the whole run itself
	if drv == nil && o.tier == 1 {
		runArgs = append(runArgs, "--boundary", "netns", "--boundary-name", o.name)
	}
	if pinnedFile != "" {
		runArgs = append(runArgs, "-package-gate", pinnedFile)
	}
	if unattended {
		runArgs = append(runArgs, "-unattended")
		fmt.Fprintln(os.Stderr, "==> ci profile: no one answers; anything policy would pause is refused at once")
	}
	// The agent works on this one project: the GitHub key only goes with
	// requests about its repository, not every repository the key can see.
	if o.ghScope == sandbox.ScopeRepo {
		if or := githubRepoOf(project); or != "" {
			runArgs = append(runArgs, "-scope-repo", or)
			fmt.Fprintf(os.Stderr, "==> the GitHub key is limited to %s for this run (-github-scope all to lift it)\n", or)
		} else {
			// No GitHub repository could be read from the project's remote:
			// rather than hand over a key that reaches every repository,
			// this run gets none.
			runArgs = append(runArgs, "-scope-repo", scopeRepoNone)
			fmt.Fprintln(os.Stderr, "==> no GitHub repository found in the project's origin remote: the GitHub key is withheld for this run (-github-scope all to give it unscoped)")
		}
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
	events.Emit(sandbox.Event{Event: sandbox.EventProxyStarted})
	proxyUp = true
	// the certificate is created by the first `ovara run`; copy it now if it was not there before
	if _, err := os.Stat(caPub); err != nil {
		if b, err := os.ReadFile(inDir(o.dir, cfg.CACertFile)); err == nil {
			_ = os.WriteFile(caPub, b, 0o644) //nolint:gosec // the PUBLIC certificate: the agent must be able to read it
		}
	}
	receiptsBefore = receiptLineCount(inDir(o.dir, cfg.ReceiptsFile))

	// 4. the agent, inside
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigs)
	gw := gateway.New(cfg.GatewayURL, cfg.GatewayToken, cfg.Environment)
	gate := newCommandGate(gw, o.dir, time.Duration(cfg.EscalateTimeoutSec)*time.Second, !o.noGate, o.cmd, events)
	gate.unattended = unattended
	a := &boxAgent{
		dir: o.dir, cfg: cfg, ws: ws, runID: runID, runDir: runDir, home: home, caPub: caPub, port: port,
		envs: o.envs, cmd: o.cmd, gate: gate, noGate: o.noGate, sigs: sigs,
		user: o.user, uid: uid, gid: gid, name: o.name, tier1FS: o.tier1FS, visibleProcs: o.visibleProcs, image: o.image, mounts: o.mounts, pids: o.pids, memory: o.memory, cpus: o.cpus, selfPath: self,
		allowUserNS: x.allowUserNS, allowDebuggers: x.allowDebuggers,
	}
	events.Emit(sandbox.Event{Event: sandbox.EventAgentStarted, Command: strings.Join(o.cmd, " ")})
	var exitCode int
	switch {
	case drv != nil:
		exitCode, err = runVM(a, drv, vmBin)
	case o.tier == 2:
		exitCode, err = runTier2(a)
	default:
		exitCode, err = runTier1(a)
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "==> agent exited with status %d\n", exitCode)
	summary.ExitCode = exitCode
	events.Emit(sandbox.Event{Event: sandbox.EventAgentExited, Code: &exitCode})
	summary.Requests, summary.Hosts = printRunSummary(inDir(o.dir, cfg.ReceiptsFile), receiptsBefore)
	gate.summary()
	summary.Commands = gate.tally()

	// how the changes end, for the summary and the stream
	ended := func(event string, ev sandbox.Event) {
		summary.CommitBack = strings.TrimPrefix(event, "commit_back.")
		ev.Event = event
		events.Emit(ev)
	}
	// 5. what comes back
	if o.noCommitBack {
		summary.Outcome = sandbox.OutcomeKept
		ended(sandbox.EventCommitBackDisabled, sandbox.Event{})
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
		summary.Outcome = sandbox.OutcomeClean
		ended(sandbox.EventCommitBackNothing, sandbox.Event{})
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
	}, o.allowBinary)
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
		summary.Outcome = sandbox.OutcomeKept
		ended(sandbox.EventCommitBackKept, sandbox.Event{})
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
		summary.Outcome = sandbox.OutcomeKept
		ended(sandbox.EventCommitBackRefused, sandbox.Event{})
		return nil
	case decisionEscalate:
		if unattended {
			fmt.Fprintln(os.Stderr, "==> ci profile: the commit-back needs a person, and no one answers; the workspace is kept (allow fs.commit_back in policy to bring changes back unattended)")
			summary.Outcome = sandbox.OutcomeKept
			ended(sandbox.EventCommitBackRefused, sandbox.Event{})
			return nil
		}
		id, err := gw.CreateApprovalFor(ctx, d, "fs.commit_back", resource)
		if err != nil {
			return fmt.Errorf("gateway: %w", err)
		}
		fmt.Fprintf(os.Stderr, "==> waiting for you to approve the changes (%d files, approval %s): the approval page or `ovara approvals -dir %s`\n", len(plan.allowed), id, o.dir)
		events.Emit(sandbox.Event{Event: sandbox.EventCommitBackWaiting, ApprovalID: id, Files: len(plan.allowed)})
		status, err := waitApproval(ctx, gw, id, capToApprovalTTL(o.dir, o.approveTimeout))
		if err != nil {
			return err
		}
		if status != approvalApproved {
			fmt.Fprintf(os.Stderr, "==> %s; nothing comes back, the workspace is kept\n", status)
			summary.Outcome = sandbox.OutcomeKept
			ended(sandbox.EventCommitBackNotApproved, sandbox.Event{ApprovalID: id, Status: status})
			return nil
		}
	}
	// exactly the reviewed tree, or nothing
	commit, err := ws.CommitTree(branch, snap)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "==> changes are on branch %s of %s (%s); review and merge it like a pull request\n", branch, ws.Project, commit[:12])
	summary.Outcome = sandbox.OutcomeClean
	summary.Branch, summary.Commit = branch, commit[:12]
	landedCommit = commit
	ended(sandbox.EventCommitBackLanded, sandbox.Event{Branch: branch, Commit: commit[:12], Files: len(plan.allowed)})
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

// serveGate answers the box's command gate: the first connection only (the
// box's PID 1), one decision per line, until it closes.
func serveGate(ln net.Listener, gate *commandGate) {
	c, err := ln.Accept()
	ln.Close()
	if err != nil {
		return
	}
	defer c.Close()
	serveGateConn(c, json.NewDecoder(c), gate.decide)
}

// checkTier1Tools fails early, with a clear message, when the host is
// missing a command the tier 1 network boundary needs. Without it the
// boundary script fails mid-setup and `ovara run` only times out
// ("did not come up"), which does not say what is wrong.
func checkTier1Tools() error {
	if _, err := exec.LookPath("ip"); err != nil {
		return errors.New("ovara box -tier 1 needs the `ip` command for its network namespace (install iproute2), or use -tier 2 for a container")
	}
	if _, err := exec.LookPath("iptables"); err != nil {
		if _, err := exec.LookPath("nft"); err != nil {
			return errors.New("ovara box -tier 1 needs `iptables` or `nft` to firewall the boundary (install iptables or nftables), or use -tier 2 for a container")
		}
	}
	return nil
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
	return imageNotFound(image)
}

// imageNotFound says how to build a missing box image from the Ovara
// repository: an -agent-image one is the box image with the agent added.
func imageNotFound(image string) error {
	if agent, ok := strings.CutPrefix(image, boxDefaultImage+"-"); ok && boxAgents[agent] {
		return fmt.Errorf("box image %q not found: build it from the Ovara repository with `docker build -t %s box/` then `docker build --build-arg AGENT=%s -t %s box/agents`, or pass -image", image, boxDefaultImage, agent, image)
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

// commandGate decides each exec in the box through the gateway.
type commandGate struct {
	unattended bool // ci profile: a pause is a refusal, no approval is opened
	gw         *gateway.Client
	dir        string
	timeout    time.Duration
	on         bool
	started    bool // the agent itself has been exec'd; before that, our wrappers run
	mu         sync.Mutex
	counts     map[string]int
	// launch is the agent command the person gave; launched is set once
	// the first checked exec has been compared with it
	launch   []string
	launched bool
	events   *sandbox.Events // the run's stream; nil writes nothing
}

func newCommandGate(gw *gateway.Client, dir string, timeout time.Duration, on bool, launch []string, events *sandbox.Events) *commandGate {
	return &commandGate{gw: gw, dir: dir, timeout: timeout, on: on, counts: map[string]int{}, launch: launch, events: events}
}

// emit reports one decision on the run's stream.
func (g *commandGate) emit(event, command, approvalID, status string) {
	g.events.Emit(sandbox.Event{Event: event, Command: command, ApprovalID: approvalID, Status: status})
}

// skip exempts the launcher's own box-init -tier1, the first program in
// the tree; what it execs next is the agent.
func (g *commandGate) skip(e boxgate.Exec) bool {
	if g.started {
		return false
	}
	g.started = true
	return len(e.Argv) >= 3 && e.Argv[1] == boxInitCmd && e.Argv[2] == "-tier1"
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
		g.emit(sandbox.EventCommandRefused, raw, "", "")
		return boxgate.Deny
	}
	switch d.Decision {
	case decisionAllow:
		g.count(countAllowed)
		g.emit(sandbox.EventCommandAllowed, raw, "", "")
		return boxgate.Allow
	case decisionDeny:
		fmt.Fprintf(os.Stderr, "[ovara] command refused by policy: %s\n", shown)
		g.count(countDenied)
		g.emit(sandbox.EventCommandRefused, raw, "", "")
		return boxgate.Deny
	}
	if launch {
		// the person typed this command to start the box; asking them to
		// approve it (say, an agent started with its own checks off)
		// would be asking them what they just said
		g.count(countAllowed)
		g.emit(sandbox.EventCommandAllowed, raw, "", "")
		return boxgate.Allow
	}
	if g.unattended {
		fmt.Fprintf(os.Stderr, "[ovara] command refused (needs a person; unattended run): %s\n", shown)
		g.count(countDenied)
		g.emit(sandbox.EventCommandRefused, raw, "", "")
		return boxgate.Deny
	}
	id, err := g.gw.CreateApprovalFor(context.Background(), d, "shell", "shell:"+line)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ovara] command gate: could not open an approval, refusing: %s (%v)\n", shown, err)
		g.count(countDenied)
		g.emit(sandbox.EventCommandRefused, raw, "", "")
		return boxgate.Deny
	}
	fmt.Fprintf(os.Stderr, "[ovara] command paused for your approval (%s): %s\n", id, shown)
	g.count(countPaused)
	g.emit(sandbox.EventCommandPaused, raw, id, "")
	status, err := waitApproval(context.Background(), g.gw, id, g.timeout)
	if err != nil || status != approvalApproved {
		if status == "" {
			status = approvalError
		}
		fmt.Fprintf(os.Stderr, "[ovara] command %s: %s\n", status, shown)
		g.count(countDenied)
		g.emit(sandbox.EventCommandNotApproved, raw, id, status)
		return boxgate.Deny
	}
	g.count(countApproved)
	g.emit(sandbox.EventCommandApproved, raw, id, "")
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

// tally is the gate's part of the run's summary; nil when the gate was off.
func (g *commandGate) tally() *sandbox.Counts {
	if !g.on {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return &sandbox.Counts{Allowed: g.counts[countAllowed], Paused: g.counts[countPaused], Approved: g.counts[countApproved], Denied: g.counts[countDenied]}
}

func waitApproval(ctx context.Context, gw *gateway.Client, id string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		st, err := gw.ApprovalStatus(ctx, id)
		if err == nil {
			st = settleApproval(ctx, gw, id, st) // single use: claimed before the command runs
		}
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

// githubRepoOf returns "owner/repo" for a project whose origin remote is on
// github.com, or "".
func githubRepoOf(project string) string {
	out, err := exec.Command("git", "-C", project, "config", "--get", "remote.origin.url").Output() //nolint:gosec // the project path the person gave
	if err != nil {
		return ""
	}
	return parseGitHubRemote(strings.TrimSpace(string(out)))
}
