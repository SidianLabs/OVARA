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

// bs is a backslash, for writing JSON escapes in test bodies.
const bs = `\`

// The wrapper relays what it checked, in both directions: the server gets
// the canonical encoding of each client line, the client the canonical
// encoding of each server line. A line that readers could disagree on is
// refused, not relayed with one reading decided and another acted on.
func TestMCPWrapForwardsCanonicalLines(t *testing.T) {
	g, gwURL := newWrapGateway(t)
	g.set(g.byAction, mcp.ActionTools, "allow")
	g.set(g.byAction, mcp.ActionToolCall, "allow")
	store, _ := mcp.OpenStore(filepath.Join(t.TempDir(), "mcp_pins.json"))
	w := newWrapper(store, &gatewayAsker{gw: gateway.New(gwURL, "", "test"), timeout: 3 * time.Second, poll: 10 * time.Millisecond}, "stdio:canon")

	clientR, clientW := io.Pipe()
	outR, outW := io.Pipe()
	srvInR, srvInW := io.Pipe()
	srvOutR, srvOutW := io.Pipe()
	var mu sync.Mutex
	var got []string
	go func() {
		sc := bufio.NewScanner(srvInR)
		for sc.Scan() {
			line := sc.Text()
			mu.Lock()
			got = append(got, line)
			mu.Unlock()
			switch {
			case strings.Contains(line, `"id":1,`):
				// white space, unsorted keys and an escaped name: the
				// client must read it canonical
				fmt.Fprintln(srvOutW, `{ "result" : {"tools":[`+wrapSearch+`]}, "id":1, "jsonrpc":"2.0" }`)
			case strings.Contains(line, `"id":3,`):
				fmt.Fprintln(srvOutW, `{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"`+bs+`u0041<b>"}]}}`)
			}
		}
		srvOutW.Close()
	}()
	done := make(chan error, 1)
	go func() { done <- w.relay(context.Background(), clientR, outW, srvInW, srvOutR); outW.Close() }()
	out := bufio.NewScanner(outR)
	call := func(line string) string {
		t.Helper()
		if _, err := fmt.Fprintln(clientW, line); err != nil {
			t.Fatal(err)
		}
		ch := make(chan string, 1)
		go func() {
			if out.Scan() {
				ch <- out.Text()
			} else {
				ch <- ""
			}
		}()
		select {
		case s := <-ch:
			return s
		case <-time.After(10 * time.Second):
			t.Fatalf("no answer to %s", line)
		}
		return ""
	}

	list := call(`  {"method" : "tools/list", "jsonrpc":"2.0", "id":1}  `)
	wantList := `{"id":1,"jsonrpc":"2.0","result":{"tools":[{"description":"Search the web.","inputSchema":{"type":"object"},"name":"search"}]}}`
	if list != wantList {
		t.Fatalf("the client read %s, want the canonical list %s", list, wantList)
	}
	answer := call(`{"params":{"arguments":{"q":"caf` + bs + `u00e9 ` + bs + `/x","n":1.50},"name":"search"},"method":"tools/call","id":3,"jsonrpc":"2.0"}`)
	if want := `{"id":3,"jsonrpc":"2.0","result":{"content":[{"text":"A<b>","type":"text"}]}}`; answer != want {
		t.Fatalf("the client read %s, want %s", answer, want)
	}
	// Go keeps the last of two "method" members, so this is a ping to
	// Go; a server that keeps the first runs a tool nobody decided.
	m := call(`{"jsonrpc":"2.0","id":7,"method":"tools/call","method":"ping","params":{"name":"evil"}}`)
	if !strings.Contains(m, "mcp_message_ambiguous") {
		t.Fatalf("duplicate keys: %s", m)
	}

	mu.Lock()
	lines := append([]string(nil), got...)
	mu.Unlock()
	want := []string{
		`{"id":1,"jsonrpc":"2.0","method":"tools/list"}`,
		"{\"id\":3,\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"arguments\":{\"n\":1.50,\"q\":\"caf\u00e9 /x\"},\"name\":\"search\"}}",
	}
	if len(lines) != len(want) {
		t.Fatalf("the server received %q, want %q", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d: the server received %s, want %s", i, lines[i], want[i])
		}
	}
	clientW.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
