//go:build linux

package main

// `ovara box-init`: PID 1 of a tier 2 box (a container). Not for people to
// run; `ovara box -tier 2` starts it as the container's entrypoint. (With
// -tier1 it is instead the last step before a tier 1 agent: box_tier1.go.)
//
// It runs as root inside the container, with only the capabilities it needs
// (SETUID and SETGID to drop to the agent's uid, KILL to stop the agent's
// processes), and:
//
//   - relays 127.0.0.1:<port> inside the container to Ovara's proxy through
//     a Unix socket the host mounted at /run/ovara/proxy.sock. The container
//     has no network interface but loopback, so this relay is the only way
//     out, and it leads only to the proxy;
//   - connects to the host's command gate at /run/ovara/gate.sock;
//   - starts the agent as the unprivileged box user, traced, and asks the
//     host about every program the agent's tree starts (internal/boxgate).
//
// /run/ovara is a directory only root can enter, so the agent can use
// neither socket directly; it can reach the proxy only through the relay.
// If the host side goes away, the relay has nowhere to go and every command
// is refused: the box fails closed.

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"ovara.proxy/internal/boxgate"
	"ovara.proxy/internal/boxseccomp"
)

// box-init -tier1 enters namespaces and drops credentials on the thread
// that then calls exec: keep main on the main thread from the start, so
// the agent takes over the process as it is.
func init() {
	if len(os.Args) > 1 && os.Args[1] == boxInitCmd {
		runtime.LockOSThread()
	}
}

func cmdBoxInit(args []string) error {
	fs := flag.NewFlagSet(boxInitCmd, flag.ContinueOnError)
	uid := fs.Int("uid", boxContainerUID, "uid the agent runs as")
	gid := fs.Int("gid", boxContainerUID, "gid the agent runs as")
	proxyAddr := fs.String("proxy", "127.0.0.1:9443", "address inside the box where the proxy relay listens")
	gateOn := fs.Bool("gate", true, "check every exec with the host's command gate")
	tier1 := fs.Bool("tier1", false, "tier 1: become the agent described by the spec on fd 3 (box_tier1.go)")
	vmSpec := fs.String("vm", "", "inside a VM: run the agent described by this spec file (box_vm_guest.go)")
	execShim := fs.Bool("exec-shim", false, "the shim that installs the seccomp filter and becomes the agent (box_shim_linux.go)")
	allowUserNS := fs.Bool("allow-userns", false, "seccomp opt-out: let the agent create namespaces and use the mount calls")
	allowDebuggers := fs.Bool("allow-debuggers", false, "seccomp opt-out: let the agent use ptrace, process_vm_* and perf_event_open")
	vmStop := fs.String("vm-stop", "", "inside a VM: stop the run started with this spec file, keeping its workspace")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *tier1 {
		return runTier1Init()
	}
	seccompOpts := boxseccomp.Options{AllowUserNamespaces: *allowUserNS, AllowDebuggers: *allowDebuggers}
	if *execShim {
		return runExecShim(fs.Args(), seccompOpts)
	}
	if *vmStop != "" {
		return runVMStop(*vmStop)
	}
	if *vmSpec != "" {
		code, err := runVMGuest(*vmSpec)
		if err != nil {
			return err
		}
		os.Exit(code)
	}
	argv := fs.Args()
	if len(argv) == 0 {
		return errors.New("box-init: no agent command")
	}
	if *uid <= 0 || *gid <= 0 {
		return errors.New("box-init: the agent must not run as root")
	}

	// the only way out: loopback relay to the host's proxy socket
	ln, err := net.Listen("tcp", *proxyAddr)
	if err != nil {
		return fmt.Errorf("box-init: proxy relay: %w", err)
	}
	go relayTo(ln, func() (net.Conn, error) { return net.Dial("unix", filepath.Join(boxSockDir, boxProxySock)) })

	// The agent starts through the exec shim, as the agent's user, so that it
	// is the one under the box's seccomp filter and this process, the gate's
	// tracer, is not (box_shim_linux.go). It is the same binary, mounted
	// read-only at the path box-init itself runs from.
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("box-init: %w", err)
	}
	shim := shimArgv(self, seccompOpts, argv)
	cmd := exec.Command(shim[0], shim[1:]...) //nolint:gosec // our own binary, then the agent command the person asked `ovara box` to run
	cmd.Env = os.Environ()
	cmd.Dir = "/work"
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uint32(*uid), Gid: uint32(*gid), Groups: []uint32{}}, //nolint:gosec // checked > 0 above
	}

	// docker stop sends SIGTERM to PID 1: pass it to every process in the
	// box (kill(-1) reaches all of them except PID 1 itself). SIGINT comes
	// from the terminal to the whole foreground group already.
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT)
	go func() {
		for s := range sigs {
			if s == syscall.SIGINT {
				continue
			}
			_ = syscall.Kill(-1, s.(syscall.Signal))
		}
	}()

	code := 0
	if *gateOn {
		gc, err := net.Dial("unix", filepath.Join(boxSockDir, boxGateSock))
		if err != nil {
			return fmt.Errorf("box-init: command gate: %w (refusing to start the agent without it)", err)
		}
		g := &remoteGate{enc: json.NewEncoder(gc), dec: json.NewDecoder(gc)}
		tr := &boxgate.Tracer{Decide: g.decide, Skip: shimSkipper(), Changed: argvChanged}
		code, err = tr.Run(cmd)
		if err != nil {
			return fmt.Errorf("box-init: %w", err)
		}
	} else {
		if err := cmd.Run(); err != nil {
			var ee *exec.ExitError
			if !errors.As(err, &ee) {
				fmt.Fprintf(os.Stderr, "[ovara] %v\n", err)
				os.Exit(127)
			}
			code = ee.ExitCode()
			if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
				code = 128 + int(ws.Signal())
			}
		}
	}
	os.Exit(code)
	return nil
}
