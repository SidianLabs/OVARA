package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"ovara.proxy/internal/gateway"
	"ovara.proxy/internal/mcp"
)

// The wrapper never passes on a client line it cannot read strictly: the
// client gets a JSON-RPC parse error instead. A server line that looks
// like JSON-RPC but cannot be read strictly never reaches the client.
// Tool-call questions carry the hash of the arguments and of the line.
func TestMCPWrapRefusesUnparseableLines(t *testing.T) {
	g, gwURL := newWrapGateway(t)
	g.set(g.byAction, mcp.ActionTools, "allow")
	g.set(g.byAction, mcp.ActionToolCall, "allow")
	store, _ := mcp.OpenStore(filepath.Join(t.TempDir(), "mcp_pins.json"))
	w := newWrapper(store, &gatewayAsker{gw: gateway.New(gwURL, "", "test"), timeout: 3 * time.Second, poll: 10 * time.Millisecond}, "stdio:raw")

	clientR, clientW := io.Pipe()
	outR, outW := io.Pipe()
	srvInR, srvInW := io.Pipe()
	srvOutR, srvOutW := io.Pipe()
	var mu sync.Mutex
	var got []string
	go func() {
		// A server that records every raw line and answers the ones it
		// knows by id.
		sc := bufio.NewScanner(srvInR)
		for sc.Scan() {
			line := sc.Text()
			mu.Lock()
			got = append(got, line)
			mu.Unlock()
			switch {
			case strings.Contains(line, `"id":1,`):
				fmt.Fprintln(srvOutW, `{"jsonrpc":"2.0","id":1,"result":{"tools":[`+wrapSearch+`]}}`)
			case strings.Contains(line, `"id":2,`):
				fmt.Fprintln(srvOutW, `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"evil","inputSchema":{"x":NaN}}]}}`)
			case strings.Contains(line, `"id":3,`):
				fmt.Fprintln(srvOutW, `{"jsonrpc":"2.0","id":3,"result":{"content":[]}}`)
			}
		}
		srvOutW.Close()
	}()
	done := make(chan error, 1)
	go func() { done <- w.relay(context.Background(), clientR, outW, srvInW, srvOutR); outW.Close() }()
	c := &stdioClient{t: t, in: clientW, out: bufio.NewScanner(outR)}

	if m := c.call(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`); !strings.Contains(fmt.Sprint(m["result"]), "search") {
		t.Fatalf("list: %v", m)
	}
	for _, line := range []string{
		`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"search","arguments":{"q":NaN}}}`,
		`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"search","arguments":{}}} {}`,
		`{"a":1,`,
		"\xff\xfe{\x00",
	} {
		m := c.call(line)
		if code, _ := errCode(m); code != -32700 {
			t.Errorf("%q: answer %v, want a parse error", line, m)
		}
	}
	// A tool list the server sends with NaN in it is refused.
	m := c.call(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if code, _ := errCode(m); code != mcp.ErrorCode || strings.Contains(fmt.Sprint(m), "evil") {
		t.Errorf("unparseable list: %v", m)
	}
	// A valid call: its question binds the arguments and the line.
	if m := c.call(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"search","arguments":{"q":"x"}}}`); m["result"] == nil {
		t.Fatalf("call: %v", m)
	}
	g.mu.Lock()
	ctx := g.contexts[len(g.contexts)-1]
	g.mu.Unlock()
	if len(ctx["arguments_sha256"]) != 64 || len(ctx["body_sha256"]) != 64 {
		t.Errorf("tool-call context: %v", ctx)
	}
	mu.Lock()
	n := len(got)
	mu.Unlock()
	if n != 3 {
		t.Errorf("the server received %d lines, want 3: %q", n, got)
	}
	clientW.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
