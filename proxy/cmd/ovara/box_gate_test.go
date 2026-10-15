package main

import (
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"ovara.proxy/internal/boxgate"
)

// startGate serves the TCP gate with token, denying `touch` and allowing
// everything else, and records every command it was asked about.
func startGate(t *testing.T, token string) (addr string, asked func() []string, done chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var mu sync.Mutex
	var seen []string
	done = make(chan struct{})
	go func() {
		defer close(done)
		serveGateTCP(ln, token, func(e boxgate.Exec) boxgate.Verdict {
			line := boxgate.CommandLine(e)
			mu.Lock()
			seen = append(seen, line)
			mu.Unlock()
			if strings.HasPrefix(line, "touch ") {
				return boxgate.Deny
			}
			return boxgate.Allow
		})
	}()
	return ln.Addr().String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}, done
}

func TestGateTCP_TokenOpensItAndDecisionsFlow(t *testing.T) {
	token, err := newGateToken()
	if err != nil {
		t.Fatal(err)
	}
	addr, asked, _ := startGate(t, token)
	g, c, err := dialGateTCP(addr, token, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if v := g.decide(boxgate.Exec{Argv: []string{"ls", "-l"}}); v != boxgate.Allow {
		t.Errorf("ls: %v, want allow", v)
	}
	if v := g.decide(boxgate.Exec{Argv: []string{"touch", "x"}}); v != boxgate.Deny {
		t.Errorf("touch: %v, want deny", v)
	}
	if got := asked(); len(got) != 2 || got[0] != "ls -l" || got[1] != "touch x" {
		t.Errorf("gate asked %q", got)
	}
}

// A connection without the token gets nothing, and the real box can still
// connect after it; once the box has, the port takes no one else.
func TestGateTCP_WrongTokenRefusedThenRealBoxServed(t *testing.T) {
	token, _ := newGateToken()
	addr, asked, _ := startGate(t, token)

	if _, _, err := dialGateTCP(addr, strings.Repeat("0", 64), 3*time.Second); err == nil {
		t.Fatal("a wrong token was accepted")
	}
	// someone sending requests without saying hello is refused too
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_ = json.NewEncoder(c).Encode(gateRequest{Argv: []string{"rm", "-rf", "/"}})
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	var r gateReply
	if err := json.NewDecoder(c).Decode(&r); err == nil {
		t.Fatalf("a request without the token was answered: %+v", r)
	}
	c.Close()
	if got := asked(); len(got) != 0 {
		t.Fatalf("the gate was asked by someone without the token: %q", got)
	}

	g, gc, err := dialGateTCP(addr, token, 5*time.Second)
	if err != nil {
		t.Fatalf("the real box was turned away: %v", err)
	}
	defer gc.Close()
	if v := g.decide(boxgate.Exec{Argv: []string{"true"}}); v != boxgate.Allow {
		t.Fatalf("true: %v", v)
	}
	if _, _, err := dialGateTCP(addr, token, 2*time.Second); err == nil {
		t.Fatal("a second connection was accepted after the box's")
	}
}

func TestGateTCP_SilentConnectionTimesOut(t *testing.T) {
	saved := gateHelloWait
	gateHelloWait = 200 * time.Millisecond
	defer func() { gateHelloWait = saved }()
	token, _ := newGateToken()
	addr, _, _ := startGate(t, token)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("a silent connection was kept open")
	}
	// and the box can still connect afterwards
	if _, gc, err := dialGateTCP(addr, token, 3*time.Second); err != nil {
		t.Fatalf("box refused after a silent connection: %v", err)
	} else {
		gc.Close()
	}
}
