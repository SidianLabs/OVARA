package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"ovara.proxy/internal/mcp"
	"ovara.runtime.gateway/pkg/server"
)

// With the real gateway and the policy `ovara init` writes: the first tool
// list pauses until a person approves it, with the definitions in front of
// them, and a tool call pauses and can be refused.
func TestMCPWrapWithTheRealGatewayAndDefaultPolicy(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a gateway")
	}
	// Not t.TempDir: the gateway runs in this process and has no way to
	// stop it short of a signal, so its stores stay open until the test
	// binary exits, and Windows cannot remove an open file.
	dir, err := os.MkdirTemp("", "ovara-mcp-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	ln.Close()
	if _, err := deploy(dir, port, true); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "proxy.json"))
	var pc map[string]any
	_ = json.Unmarshal(b, &pc)
	pc["escalate_poll_sec"], pc["escalate_timeout_sec"] = 1, 20
	b, _ = json.Marshal(pc)
	if err := os.WriteFile(filepath.Join(dir, "proxy.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	go func() { _ = server.Run("config.json") }()
	if err := waitForGateway("http://127.0.0.1:"+port, 15*time.Second); err != nil {
		t.Fatal(err)
	}
	admin, err := newAdminClient(dir)
	if err != nil {
		t.Fatal(err)
	}
	// answer resolves the next pending approval of action and returns what
	// the person saw
	answer := func(action string, approve bool) chan []string {
		seen := make(chan []string, 1)
		go func() {
			for i := 0; i < 300; i++ {
				list, _ := admin.pending()
				for _, a := range list {
					if a.ActionType == action {
						seen <- append([]string{a.Resource}, contextLines(a)...)
						_ = admin.resolve(a.ApprovalID, approve, "tester", "")
						return
					}
				}
				time.Sleep(50 * time.Millisecond)
			}
			seen <- nil
		}()
		return seen
	}

	t.Setenv("OVARA_TEST_FAKE_MCP", "1")
	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- cmdMCPWrap([]string{"-dir", dir, "-name", "real", "--", os.Args[0], "-test.run=^$"}, stdinR, stdoutW)
		stdoutW.Close()
	}()
	c := &stdioClient{t: t, in: stdinW, out: bufio.NewScanner(stdoutR)}

	seen := answer(mcp.ActionTools, true)
	if m := c.call(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`); !strings.Contains(fmt.Sprint(m), "send_email") {
		t.Fatalf("list: %v", m)
	}
	shown := strings.Join(<-seen, "\n")
	for _, want := range []string{"mcp:stdio:real tools 2 new", "MCP server: stdio:real", "tool definitions:", "+ new tool send_email", "Send an email."} {
		if !strings.Contains(shown, want) {
			t.Errorf("the approver did not see %q in:\n%s", want, shown)
		}
	}
	seen = answer(mcp.ActionToolCall, false)
	m := c.call(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"send_email","arguments":{"to":"a@b.example"}}}`)
	if code, _ := errCode(m); code != mcp.ErrorCode {
		t.Fatalf("refused call: %v", m)
	}
	shown = strings.Join(<-seen, "\n")
	if !strings.Contains(shown, "mcp:stdio:real/send_email") || !strings.Contains(shown, `arguments: {"to":"a@b.example"}`) {
		t.Errorf("the call's approval showed:\n%s", shown)
	}
	stdinW.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
