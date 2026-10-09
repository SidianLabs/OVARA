package main

// `ovara box`: run an agent in a box whose only exits go through Ovara.
//
//   ovara box [flags] <project-dir> -- <agent command...>
//
// What it does, in order (docs/box.md §6):
//   1. `ovara init` the deployment if it is missing;
//   2. copy the project into a workspace (a real clone, history included,
//      secrets left out, the host's uncommitted changes carried over);
//   3. start `ovara run --boundary netns` so the box has no network path
//      except the proxy;
//   4. run the agent inside the namespace as an unprivileged user that is
//      not the one running Ovara, with the proxy environment and no keys;
//   5. when it exits, bring its changes back as a commit on a new branch of
//      the real repository, after a person has read the diff and a policy
//      has had its say on each path.
//
// Tier 1 (this): Linux, needs root for the namespace. The agent user and
// the namespace are reused across runs; the workspace and home are fresh
// each run.

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"ovara.proxy/internal/config"
	"ovara.proxy/internal/gateway"
	"ovara.proxy/internal/workspace"
)

const (
	boxDefaultUser = "ovara-agent"
	boxRunsRoot    = "/var/lib/ovara/runs"
	boxPreviewMax  = 64 << 10
)

var keyLikeName = regexp.MustCompile(`(?i)(key|token|secret|password|passwd|credential)`)

func cmdBox(args []string) error {
	fs := flag.NewFlagSet("box", flag.ContinueOnError)
	dir := fs.String("dir", "", "Ovara deployment directory (default: ~/.ovara/box of the invoking user; created on first use)")
	name := fs.String("name", "ovara-box", "network namespace name (one box per name at a time)")
	agentUser := fs.String("user", boxDefaultUser, "unprivileged user the agent runs as (created if missing)")
	uiAddr := fs.String("ui", "127.0.0.1:9090", "approval page address (loopback only; \"off\" to disable)")
	approveTimeout := fs.Duration("approve-timeout", 10*time.Minute, "how long the commit-back waits for a person")
	keep := fs.Bool("keep", false, "keep the workspace after the run (default: kept only when something went wrong)")
	noCommitBack := fs.Bool("no-commit-back", false, "do not offer to bring changes back; keep the workspace")
	var envs, mounts multiFlag
	fs.Var(&envs, "env", "extra NAME=value for the agent (repeatable; values that look like keys are refused)")
	fs.Var(&mounts, "exclude", "extra path glob to leave out of the workspace (repeatable; .ovaraignore is read too)")
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
	if os.Geteuid() != 0 {
		return errors.New("ovara box needs root for the network namespace: run it with sudo (the agent itself runs as an unprivileged user)")
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
	uid, gid, err := ensureUser(*agentUser)
	if err != nil {
		return err
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
	ws, err := workspace.Create(project, filepath.Join(runDir, "work"), workspace.Options{ExtraExcludes: mounts})
	if err != nil {
		return err
	}
	for _, p := range ws.Excluded {
		fmt.Fprintf(os.Stderr, "    left out: %s\n", p)
	}
	if err := chownAll(ws.Dir, uid, gid); err != nil {
		return err
	}
	if err := os.Chown(home, uid, gid); err != nil {
		return err
	}
	// the PUBLIC certificate, where the agent can read it (the deployment dir is 0700)
	caPub := filepath.Join(runDir, "ovara-ca.pem")
	if b, err := os.ReadFile(inDir(*dir, cfg.CACertFile)); err == nil {
		os.WriteFile(caPub, b, 0o644)
	}
	outcome := "failed"
	defer func() {
		if *keep || *noCommitBack || outcome != "clean" {
			fmt.Fprintf(os.Stderr, "==> workspace kept at %s\n", ws.Dir)
			return
		}
		os.RemoveAll(runDir)
		os.Remove(workspace.MetaFile(ws.Dir))
	}()

	// 3. Ovara itself, with the boundary
	run := exec.Command(os.Args[0], "run", "-dir", *dir, "--boundary", "netns", "--boundary-name", *name, "-ui", *uiAddr)
	run.Stdout = os.Stderr
	run.Stderr = os.Stderr
	run.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := run.Start(); err != nil {
		return err
	}
	stopRun := func() {
		run.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { run.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			run.Process.Kill()
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
			os.WriteFile(caPub, b, 0o644)
		}
	}
	receiptsBefore := countLines(inDir(*dir, cfg.ReceiptsFile))

	// 4. the agent, inside
	proxyIP := boundaryProxyIP(boundarySubnetIdx(*name))
	vars, _, err := agentEnv(*dir, cfg, proxyIP)
	if err != nil {
		return err
	}
	env := []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin",
		"HOME=" + home, "USER=" + *agentUser, "LOGNAME=" + *agentUser,
		"TERM=" + envOr("TERM", "xterm"), "LANG=" + envOr("LANG", "C.UTF-8"),
		"NO_PROXY=127.0.0.1,localhost", "no_proxy=127.0.0.1,localhost",
		"OVARA_BOX=1", "OVARA_WORKSPACE=" + ws.Dir,
	}
	caIn := inDir(*dir, cfg.CACertFile)
	for _, v := range vars {
		val := v.value
		if val == caIn {
			val = caPub
		}
		env = append(env, v.name+"="+val)
	}
	env = append(env, envs...)
	agentArgs := []string{"netns", "exec", *name, "runuser", "-u", *agentUser, "--", "env", "-i"}
	agentArgs = append(agentArgs, env...)
	agentArgs = append(agentArgs, agentCmd...)
	agent := exec.Command("ip", agentArgs...)
	agent.Dir = ws.Dir
	agent.Stdin, agent.Stdout, agent.Stderr = os.Stdin, os.Stdout, os.Stderr
	agent.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	fmt.Fprintf(os.Stderr, "==> running as %s in %s (network only through Ovara at %s:%s)\n", *agentUser, ws.Dir, proxyIP, port)
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigs)
	if err := agent.Start(); err != nil {
		return fmt.Errorf("starting the agent: %w", err)
	}
	agentDone := make(chan error, 1)
	go func() { agentDone <- agent.Wait() }()
	var agentErr error
	select {
	case agentErr = <-agentDone:
	case s := <-sigs:
		fmt.Fprintf(os.Stderr, "\n==> %s: stopping the agent\n", s)
		syscall.Kill(-agent.Process.Pid, syscall.SIGTERM)
		select {
		case agentErr = <-agentDone:
		case <-time.After(10 * time.Second):
			syscall.Kill(-agent.Process.Pid, syscall.SIGKILL)
			agentErr = <-agentDone
		}
	}
	exitCode := 0
	if agentErr != nil {
		var ee *exec.ExitError
		if errors.As(agentErr, &ee) {
			exitCode = ee.ExitCode()
		} else {
			return agentErr
		}
	}
	fmt.Fprintf(os.Stderr, "==> agent exited with status %d\n", exitCode)
	printBoxSummary(inDir(*dir, cfg.ReceiptsFile), receiptsBefore)

	// 5. what comes back
	if *noCommitBack {
		outcome = "kept"
		return nil
	}
	changes, err := ws.Changes()
	if err != nil {
		return err
	}
	if len(changes) == 0 {
		fmt.Fprintln(os.Stderr, "==> the agent changed nothing")
		outcome = "clean"
		return nil
	}
	branch := "ovara/box-" + runID
	gw := gateway.New(cfg.GatewayURL, cfg.GatewayToken, cfg.Environment)
	ctx := context.Background()
	var denied, allowed []string
	for _, c := range changes {
		d, err := gw.CheckAction(ctx, "fs.commit_back.path", "path:"+c.Path, map[string]string{"status": c.Status})
		if err != nil {
			return fmt.Errorf("gateway: %w", err)
		}
		if d.Decision == "deny" {
			denied = append(denied, c.Path)
		} else {
			allowed = append(allowed, c.Path)
		}
	}
	for _, p := range denied {
		fmt.Fprintf(os.Stderr, "    policy keeps out: %s\n", p)
	}
	if len(allowed) == 0 {
		fmt.Fprintln(os.Stderr, "==> every changed path is kept out by policy; nothing comes back")
		outcome = "kept"
		return nil
	}
	preview, err := ws.Preview(boxPreviewMax)
	if err != nil {
		return err
	}
	ctxLines := map[string]string{
		"files":    strconv.Itoa(len(allowed)) + " path(s): " + strings.Join(allowed, ", "),
		"branch":   branch,
		"diff":     preview,
		"kept_out": strings.Join(denied, ", "),
	}
	resource := fmt.Sprintf("commit:%s (%d files)", filepath.Base(ws.Project), len(allowed))
	d, err := gw.CheckAction(ctx, "fs.commit_back", resource, ctxLines)
	if err != nil {
		return fmt.Errorf("gateway: %w", err)
	}
	switch d.Decision {
	case "deny":
		fmt.Fprintln(os.Stderr, "==> policy refuses the commit-back; the workspace is kept")
		outcome = "kept"
		return nil
	case "escalate":
		id, err := gw.CreateApprovalFor(ctx, d, "fs.commit_back", resource)
		if err != nil {
			return fmt.Errorf("gateway: %w", err)
		}
		fmt.Fprintf(os.Stderr, "==> waiting for you to approve the changes (%d files, approval %s): the approval page or `ovara approvals -dir %s`\n", len(allowed), id, *dir)
		status, err := waitApproval(ctx, gw, id, *approveTimeout)
		if err != nil {
			return err
		}
		if status != "approved" {
			fmt.Fprintf(os.Stderr, "==> %s; nothing comes back, the workspace is kept\n", status)
			outcome = "kept"
			return nil
		}
	}
	commit, err := ws.CommitBack(branch, denied)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "==> changes are on branch %s of %s (%s); review and merge it like a pull request\n", branch, ws.Project, commit[:12])
	outcome = "clean"
	if exitCode != 0 {
		return fmt.Errorf("agent exited with status %d", exitCode)
	}
	return nil
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
		n-skip, counts["allow"], counts["escalate"], counts["deny"], len(hosts))
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
