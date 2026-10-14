package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ovara.proxy/internal/config"
)

// If the approval page's port is taken, ovara run stops (unless told to run
// without the page): a page someone else serves there would be the one a
// person opens.
func TestOpenUI_TakenPortStopsTheRun(t *testing.T) {
	dir := t.TempDir()
	cfgJSON := `{"server_port":"1","listen_addr":"127.0.0.1","operator_tokens":["op"]}`
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(cfgJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	squatter, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer squatter.Close()
	addr := squatter.Addr().String()
	url, err := openUI(addr, false, &config.Config{})
	if err == nil || url != "" || !strings.Contains(err.Error(), "-no-ui") {
		t.Fatalf("taken port: url=%q err=%v", url, err)
	}
	if url, err := openUI(addr, true, &config.Config{}); err != nil || url != "" {
		t.Fatalf("-no-ui: url=%q err=%v", url, err)
	}
	if url, err := openUI("127.0.0.1:0", false, &config.Config{}); err != nil || !strings.Contains(url, "/#t=") {
		t.Fatalf("free port: url=%q err=%v", url, err)
	}
}
