//go:build linux

package main

// `ovara box-init`: PID 1 of a tier 2 box (a container). Not for people to
// run; `ovara box -tier 2` starts it as the container's entrypoint.
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
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	"ovara.proxy/internal/boxgate"
)

const (
	boxSockDir   = "/run/ovara"
	boxProxySock = "proxy.sock"
	boxGateSock  = "gate.sock"
)

// gateRequest and gateReply are the command gate's wire format between
// box-init (inside) and `ovara box` (host): one JSON object per line.
type gateRequest struct {
	Argv []string `json:"argv"`
	Exe  string   `json:"exe,omitempty"`
	Cwd  string   `json:"cwd,omitempty"`
}

type gateReply struct {
	Allow bool `json:"allow"`
}

func cmdBoxInit(args []string) error {
	fs := flag.NewFlagSet("box-init", flag.ContinueOnError)
	uid := fs.Int("uid", boxContainerUID, "uid the agent runs as")
	gid := fs.Int("gid", boxContainerUID, "gid the agent runs as")
	proxyAddr := fs.String("proxy", "127.0.0.1:9443", "address inside the box where the proxy relay listens")
	gateOn := fs.Bool("gate", true, "check every exec with the host's command gate")
	if err := fs.Parse(args); err != nil {
		return err
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

	cmd := exec.Command(argv[0], argv[1:]...) //nolint:gosec // the agent command is what the person asked `ovara box` to run
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
		tr := &boxgate.Tracer{Decide: g.decide}
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

// remoteGate asks the host for each exec. Any failure to get an answer is a
// refusal.
type remoteGate struct {
	enc *json.Encoder
	dec *json.Decoder
}

func (g *remoteGate) decide(e boxgate.Exec) boxgate.Verdict {
	if err := g.enc.Encode(gateRequest{Argv: e.Argv, Exe: e.Exe, Cwd: e.Cwd}); err != nil {
		fmt.Fprintf(os.Stderr, "[ovara] command gate gone, refusing: %s\n", boxgate.CommandLine(e))
		return boxgate.Deny
	}
	var r gateReply
	if err := g.dec.Decode(&r); err != nil || !r.Allow {
		return boxgate.Deny
	}
	return boxgate.Allow
}

// relayTo accepts on ln and pipes each connection to a fresh dial().
func relayTo(ln net.Listener, dial func() (net.Conn, error)) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			u, err := dial()
			if err != nil {
				return
			}
			defer u.Close()
			pipe(c, u)
		}()
	}
}

// pipe copies both ways until either side is done, then closes both.
func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}
