package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"ovara.proxy/internal/boxgate"
)

// The command gate's wire format between box-init (inside the box) and
// `ovara box` (on the host): one JSON object per line, a request for each
// program the agent's tree starts and a yes or no for each.
//
// Tier 2 carries it over a Unix socket in a directory only root can enter.
// A VM carries it over TCP to the host, and the guest's lockdown lets the
// whole guest reach that port, so the connection opens with a token that
// only box-init (root in the guest) holds. Without it an agent could put
// requests of its own to the gate: approval prompts for programs that are
// not running, whose answers could then be remembered for the real ones.

type gateRequest struct {
	Argv []string `json:"argv"`
	Exe  string   `json:"exe,omitempty"`
	Cwd  string   `json:"cwd,omitempty"`
}

type gateReply struct {
	Allow bool `json:"allow"`
}

// gateHello opens a TCP gate connection; gateWelcome accepts it.
type gateHello struct {
	Token string `json:"token"`
}

type gateWelcome struct {
	OK bool `json:"ok"`
}

// gateHelloWait is how long a connection has to present its token (a
// variable so tests can shorten it).
var gateHelloWait = 5 * time.Second

// newGateToken is a fresh per-run token for the TCP gate.
func newGateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// remoteGate asks the host for each exec. Any failure to get an answer is a
// refusal.
type remoteGate struct {
	enc *json.Encoder
	dec *json.Decoder
}

func (g *remoteGate) decide(e boxgate.Exec) boxgate.Verdict {
	if err := g.enc.Encode(gateRequest{Argv: e.Argv, Exe: e.Exe, Cwd: e.Cwd}); err != nil {
		fmt.Fprintf(os.Stderr, "[ovara] command gate gone, refusing: %s\n", termSafe(boxgate.CommandLine(e)))
		return boxgate.Deny
	}
	var r gateReply
	if err := g.dec.Decode(&r); err != nil || !r.Allow {
		return boxgate.Deny
	}
	return boxgate.Allow
}

// serveGateConn answers one connection's requests until it closes.
func serveGateConn(c net.Conn, dec *json.Decoder, decide func(boxgate.Exec) boxgate.Verdict) {
	enc := json.NewEncoder(c)
	for {
		var req gateRequest
		if err := dec.Decode(&req); err != nil {
			return
		}
		v := decide(boxgate.Exec{Exe: req.Exe, Argv: req.Argv, Cwd: req.Cwd})
		if err := enc.Encode(gateReply{Allow: v == boxgate.Allow}); err != nil {
			return
		}
	}
}

// serveGateTCP accepts connections until one presents token, answers that
// one alone, and stops listening. A connection with a wrong token, or none
// within gateHelloWait, is closed unanswered.
func serveGateTCP(ln net.Listener, token string, decide func(boxgate.Exec) boxgate.Verdict) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_ = c.SetReadDeadline(time.Now().Add(gateHelloWait))
		dec := json.NewDecoder(c)
		var h gateHello
		if err := dec.Decode(&h); err != nil || subtle.ConstantTimeCompare([]byte(h.Token), []byte(token)) != 1 {
			fmt.Fprintln(os.Stderr, "[ovara] command gate: a connection without the run's token was refused")
			c.Close()
			continue
		}
		_ = c.SetReadDeadline(time.Time{})
		if err := json.NewEncoder(c).Encode(gateWelcome{OK: true}); err != nil {
			c.Close()
			continue
		}
		ln.Close()
		serveGateConn(c, dec, decide)
		c.Close()
		return
	}
}

// dialGateTCP connects box-init inside a VM to the host's gate.
func dialGateTCP(addr, token string, timeout time.Duration) (*remoteGate, net.Conn, error) {
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, nil, err
	}
	_ = c.SetDeadline(time.Now().Add(timeout))
	enc, dec := json.NewEncoder(c), json.NewDecoder(c)
	var w gateWelcome
	if err := enc.Encode(gateHello{Token: token}); err != nil {
		c.Close()
		return nil, nil, err
	}
	if err := dec.Decode(&w); err != nil || !w.OK {
		c.Close()
		return nil, nil, errors.New("the host's command gate did not accept this box")
	}
	_ = c.SetDeadline(time.Time{})
	return &remoteGate{enc: enc, dec: dec}, c, nil
}
