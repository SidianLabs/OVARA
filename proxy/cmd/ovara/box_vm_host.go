//go:build linux || darwin

package main

// `ovara box -vm NAME`: the box inside a Linux VM, Ovara and its keys on the
// host (docs/box.md §10.1). On macOS this is how the box runs at all.
//
// Order of a run:
//
//  1. the command gate listens on the host, for the guest only, behind a
//     per-run token; the proxy is relayed there too when the guest reaches
//     the host on an address other than loopback;
//  2. the VM is created with its network locked to those two ports, and
//     verified from inside before anything else goes in;
//  3. the workspace (as one tar, so a link in the project cannot pull a
//     host file into the guest), Ovara's CA, the Linux ovara binary and the
//     guest spec go in;
//  4. box-init -vm runs the agent there (box_vm_guest.go);
//  5. the workspace comes back as one tar, is unpacked strictly into a fresh
//     directory and replaces the host's copy; the commit-back takes it from
//     there exactly as for the other tiers;
//  6. the VM is deleted.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"ovara.proxy/internal/boxgate"
	"ovara.proxy/internal/vm"
)

// vmStopWait is how long a stopped run has to end in the guest and write
// its workspace (box-init gives the agent vmStopGrace of it).
var vmStopWait = 2 * time.Minute

// vmDriver returns the driver -vm names.
func vmDriver(name string) (vm.Driver, error) {
	if name == "lima" {
		return &vm.Lima{}, nil
	}
	if d, ok := testVMDriver(name); ok {
		return d, nil
	}
	return nil, fmt.Errorf("-vm %q: want lima", name)
}

// vmSpecFor sizes the VM from -cpus and -memory when given.
func vmSpecFor(a *boxAgent, proxyPort, gatePort int) (vm.Spec, error) {
	s := vm.Spec{Name: "ovara-box-" + strings.ToLower(a.runID), CPUs: min(4, runtime.NumCPU()), MemoryGiB: 8, DiskGiB: 50, ProxyPort: proxyPort, GatePort: gatePort}
	if a.cpus != "" {
		n, err := strconv.Atoi(a.cpus)
		if err != nil {
			return s, fmt.Errorf("-cpus %q: want a whole number for a VM", a.cpus)
		}
		s.CPUs = n
	}
	if a.memory != "" {
		m := strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(a.memory), "ib"), "g")
		n, err := strconv.Atoi(m)
		if err != nil {
			return s, fmt.Errorf("-memory %q: want gibibytes for a VM, e.g. 8g", a.memory)
		}
		s.MemoryGiB = n
	}
	return s, s.Validate()
}

// guestBinary is the Linux ovara the guest runs: -vm-binary, else this one
// on a Linux host, else ovara-linux-<arch> next to this one.
func guestBinary(flagged, self string) (string, error) {
	if flagged != "" {
		return flagged, nil
	}
	if runtime.GOOS == "linux" {
		return self, nil
	}
	p := filepath.Join(filepath.Dir(self), "ovara-linux-"+runtime.GOARCH)
	if _, err := os.Stat(p); err != nil {
		return "", fmt.Errorf("the VM needs the Linux build of ovara: put ovara-linux-%s (from the release, or GOOS=linux GOARCH=%s go build -o ovara-linux-%s ./cmd/ovara) next to %s, or pass -vm-binary", runtime.GOARCH, runtime.GOARCH, runtime.GOARCH, self)
	}
	return p, nil
}

func runVM(a *boxAgent, drv vm.Driver, binary string) (int, error) {
	ctx := context.Background()
	proxyPort, err := strconv.Atoi(a.port)
	if err != nil {
		return 0, fmt.Errorf("proxy port %q: %w", a.port, err)
	}
	name := "ovara-box-" + strings.ToLower(a.runID)
	// deleted whatever happens, even half made
	defer func() { _ = drv.Delete(context.Background(), name) }()
	if p, ok := drv.(interface{ Prepare(string) error }); ok {
		if err := p.Prepare(name); err != nil {
			return 0, err
		}
	}

	// 1. the gate, and the proxy where the guest can reach it
	token, err := newGateToken()
	if err != nil {
		return 0, err
	}
	host := drv.HostListen()
	gl, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		return 0, fmt.Errorf("command gate for the VM: %w", err)
	}
	defer gl.Close()
	gatePort := gl.Addr().(*net.TCPAddr).Port
	if host != "127.0.0.1" {
		pl, err := net.Listen("tcp", net.JoinHostPort(host, a.port))
		if err != nil {
			return 0, fmt.Errorf("proxy for the VM: %w", err)
		}
		defer pl.Close()
		go relayTo(pl, func() (net.Conn, error) { return net.Dial("tcp", net.JoinHostPort("127.0.0.1", a.port)) })
	}

	// 2. the VM, locked down and checked
	spec, err := vmSpecFor(a, proxyPort, gatePort)
	if err != nil {
		return 0, err
	}
	fmt.Fprintf(os.Stderr, "==> vm (%s): creating %s (%d cpus, %d GiB); the guest reaches Ovara's proxy and command gate and nothing else\n", drv.Name(), name, spec.CPUs, spec.MemoryGiB)
	if err := drv.Create(ctx, spec); err != nil {
		return 0, fmt.Errorf("vm: %w", err)
	}
	if err := drv.Verify(ctx, name); err != nil {
		return 0, fmt.Errorf("vm: refusing to run the agent: %w", err)
	}
	fmt.Fprintln(os.Stderr, "==> vm: network lockdown verified from inside the guest")

	// 3. what goes in, as one directory
	bundle, err := os.MkdirTemp(a.runDir, "vm-in-")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(bundle)
	// it becomes the guest's run directory: the agent's user must be able to
	// reach the shim and its workspace in it (the spec inside stays 0600,
	// and box-init removes it before the agent exists)
	if err := os.Chmod(bundle, 0o755); err != nil {
		return 0, err
	}
	if err := copyFile(binary, filepath.Join(bundle, "ovara"), 0o755); err != nil {
		return 0, fmt.Errorf("the Linux ovara for the guest: %w", err)
	}
	if err := copyFile(a.caPub, filepath.Join(bundle, "ca.pem"), 0o644); err != nil {
		return 0, err
	}
	if err := writeTreeFile(a.ws.Dir, filepath.Join(bundle, "tree-in.tar")); err != nil {
		return 0, fmt.Errorf("packing the workspace: %w", err)
	}
	g := drv.GuestDir()
	gWork := g + "/work"
	vars, err := agentVars(a, drv.HostName(), g+"/ca.pem")
	if err != nil {
		return 0, err
	}
	env := []string{
		"HOME=/home/" + boxDefaultUser, "USER=" + boxDefaultUser, "LOGNAME=" + boxDefaultUser,
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"TERM=" + envOr("TERM", "xterm"), "LANG=" + envOr("LANG", "C.UTF-8"),
		"NO_PROXY=" + loopbackNoProxy, "no_proxy=" + loopbackNoProxy,
		"OVARA_BOX=1", "OVARA_BOX_TIER=vm", "OVARA_WORKSPACE=" + gWork,
	}
	env = mergeEnv(append(env, vars...), a.envs)
	gspec := vmGuestSpec{
		Argv: a.cmd, Env: env, Dir: gWork, User: boxDefaultUser,
		Gate: !a.noGate, GateAddr: net.JoinHostPort(drv.HostName(), strconv.Itoa(gatePort)), GateToken: token,
		TreeIn: g + "/tree-in.tar", TreeOut: g + "/tree-out.tar",
	}
	sb, err := json.Marshal(gspec)
	if err != nil {
		return 0, err
	}
	if err := os.WriteFile(filepath.Join(bundle, "spec.json"), sb, 0o600); err != nil {
		return 0, err
	}
	if err := drv.CopyIn(ctx, name, bundle, g); err != nil {
		return 0, fmt.Errorf("vm: copying the run in: %w", err)
	}

	// 4. the agent
	var stopping atomic.Bool
	if !a.noGate {
		go serveGateTCP(gl, token, func(e boxgate.Exec) boxgate.Verdict {
			if stopping.Load() {
				return boxgate.Deny // nothing new starts while the run stops
			}
			return a.gate.decide(e)
		})
	}
	fmt.Fprintf(os.Stderr, "==> vm: running as %s in %s (network only through Ovara at %s:%s)\n", boxDefaultUser, gWork, drv.HostName(), a.port)
	runCtx, kill := context.WithCancel(ctx)
	defer kill()
	type res struct {
		code int
		err  error
	}
	done := make(chan res, 1)
	go func() {
		c, err := drv.Run(runCtx, name, []string{g + "/ovara", boxInitCmd, "-vm", g + "/spec.json"}, vm.Stdio{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr})
		done <- res{c, err}
	}()
	var r res
	select {
	case r = <-done:
	case s := <-a.sigs:
		// a signal to `ovara box` stops the agent in order: box-init in the
		// guest ends it and still writes the workspace, which comes back;
		// a second signal, or a guest that does not finish, ends the
		// command running it at once (the workspace stays as it went in)
		fmt.Fprintf(os.Stderr, "\n==> %s: stopping the agent (again to stop at once)\n", s)
		stopping.Store(true)
		go func() {
			sctx, cancel := context.WithTimeout(ctx, vmStopWait)
			defer cancel()
			_, _ = drv.Run(sctx, name, []string{g + "/ovara", boxInitCmd, "-vm-stop", g + "/spec.json"}, vm.Stdio{Stderr: os.Stderr})
		}()
		select {
		case r = <-done:
		case <-a.sigs:
			kill()
			r = <-done
		case <-time.After(vmStopWait):
			fmt.Fprintln(os.Stderr, "==> vm: the guest did not stop in time; ending it")
			kill()
			r = <-done
		}
	}
	kill()
	if r.err != nil {
		return 0, fmt.Errorf("vm: running the agent: %w", r.err)
	}
	code := r.code

	// 5. the workspace comes back
	if err := vmBringBack(ctx, drv, name, g+"/tree-out.tar", a); err != nil {
		return code, err
	}
	return code, nil
}

// vmBringBack copies the guest's workspace tar out and puts what it holds
// in place of the host's copy of the workspace.
func vmBringBack(ctx context.Context, drv vm.Driver, name, guestTar string, a *boxAgent) error {
	back, err := os.MkdirTemp(a.runDir, "vm-out-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(back)
	local := filepath.Join(back, "tree.tar")
	if err := drv.CopyOut(ctx, name, guestTar, local); err != nil {
		return fmt.Errorf("vm: copying the workspace out: %w", err)
	}
	f, err := os.Open(local) //nolint:gosec // our own temporary file
	if err != nil {
		return err
	}
	defer f.Close()
	fresh := filepath.Join(back, "work")
	if err := extractTree(f, fresh, treeMaxBytes, treeMaxEntries); err != nil {
		return err
	}
	old := a.ws.Dir + ".before-vm"
	if err := os.Rename(a.ws.Dir, old); err != nil {
		return err
	}
	if err := os.Rename(fresh, a.ws.Dir); err != nil {
		_ = os.Rename(old, a.ws.Dir)
		return err
	}
	return os.RemoveAll(old)
}

// copyFile copies src to a new file dst with mode.
func copyFile(src, dst string, mode os.FileMode) error {
	b, err := os.ReadFile(src) //nolint:gosec // a path the launcher chose
	if err != nil {
		return err
	}
	if len(b) == 0 {
		return errors.New(src + " is empty")
	}
	return os.WriteFile(dst, b, mode) //nolint:gosec // the guest needs the binary executable and the CA readable
}
