//go:build linux

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"ovara.proxy/internal/boxgate"
)

// The two tiers that need a Linux host's kernel directly (docs/box.md §4.4):
// tier 1, a user and a network namespace on this machine, and tier 2, a
// container. The rest of `ovara box` (box.go) also runs on macOS, where the
// box runs in a VM instead (box_vm_host.go).

// tier1Spec is what box-init -tier1 needs for a's agent (env holds the
// proxy token: it travels on a pipe, never on a command line).
func (a *boxAgent) tier1Spec(env []string) (tier1Spec, error) {
	spec := tier1Spec{Netns: a.name, UID: a.uid, GID: a.gid, Env: env, Argv: a.cmd, Dir: a.ws.Dir, AllowUserNS: a.allowUserNS, AllowDebuggers: a.allowDebuggers}
	if a.tier1FS == tier1FSHost {
		return spec, nil
	}
	spec.Root = filepath.Join(a.runDir, "root")
	if err := os.Mkdir(spec.Root, 0o700); err != nil {
		return spec, err
	}
	spec.VisibleProcs = a.visibleProcs
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
		"NO_PROXY=" + loopbackNoProxy, "no_proxy=" + loopbackNoProxy,
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
	// The agent starts through the exec shim, which is this very binary run
	// as the agent's user (box_shim_linux.go): it must be readable and
	// executable by everyone, not only root.
	if st, err := os.Stat(a.selfPath); err != nil || st.Mode().Perm()&0o005 != 0o005 {
		return 0, fmt.Errorf("tier 2 starts the agent through %s as the agent's user, so it must be readable and executable by everyone (chmod 755 it)", a.selfPath)
	}
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
		"NO_PROXY=" + loopbackNoProxy, "no_proxy=" + loopbackNoProxy,
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
	args = append(args, a.image, boxInitCmd,
		"-uid", strconv.Itoa(boxContainerUID), "-gid", strconv.Itoa(boxContainerUID),
		"-proxy", "127.0.0.1:"+a.port, "-gate="+strconv.FormatBool(!a.noGate),
		"-allow-userns="+strconv.FormatBool(a.allowUserNS), "-allow-debuggers="+strconv.FormatBool(a.allowDebuggers), "--")
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

func isTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
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
