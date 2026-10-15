//go:build linux

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// TestVMBox_EndToEnd runs the real `ovara box -vm` path with the network-
// namespace stand-in for a VM (internal/vm Netns): Ovara and its keys on the
// host, the guest locked to the proxy and the gate, the workspace in and out
// as tars, box-init -vm running the agent as its own user under the gate.
// Everything but the hypervisor is the code a Lima run uses.
//
// Needs root, the ovara binary built beforehand (OVARA_TEST_BINARY: CI
// builds it as the runner's user so no root-owned files reach the Go
// caches), ip, nft, git and curl. CI sets OVARA_REQUIRE_VM_E2E=1 so a
// missing piece fails instead of skipping.
func TestVMBox_EndToEnd(t *testing.T) {
	bin, dir, project := vmE2E(t)

	script := strings.Join([]string{
		"id -u > who.txt",
		"grep -E '^(Seccomp|NoNewPrivs):' /proc/self/status > status.txt",
		"echo changed-in-vm > out.txt",
		"curl -s -o /dev/null -w 'pastebin=%{http_code}\\n' https://pastebin.com/ > net.txt",
		"(curl -s --noproxy '*' -m 3 -o /dev/null https://1.1.1.1/ && echo direct=open || echo direct=blocked) >> net.txt",
		"sudo -n true 2>/dev/null && echo sudo=yes >> net.txt || echo sudo=no >> net.txt",
		"exit 4",
	}, "\n")
	cmd := exec.Command(bin, "box", "-vm", "netns-test", "-dir", dir, "-ui", "off", "-no-commit-back", "-keep", project, "--", "sh", "-c", script) //nolint:gosec // the binary under test
	cmd.Env = append(os.Environ(), "OVARA_BOX_VM_NETNS_TEST=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ovara box -vm: %v\n%s", err, out)
	}
	log := string(out)
	for _, want := range []string{
		"network lockdown verified from inside the guest",
		"agent exited with status 4",
		"command refused by policy: sudo -n true",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("output lacks %q:\n%s", want, log)
		}
	}

	work := keptWorkspace(t, dir, log)
	read := func(name string) string {
		b, _ := os.ReadFile(filepath.Join(work, name)) //nolint:gosec // test output
		return strings.TrimSpace(string(b))
	}
	if who := read("who.txt"); who == "" || who == "0" {
		t.Errorf("the agent ran as uid %q, want its own non-root user", who)
	}
	if st := read("status.txt"); !strings.Contains(st, "NoNewPrivs:\t1") || !strings.Contains(st, "Seccomp:\t2") {
		t.Errorf("the agent is not under no_new_privs and the seccomp filter:\n%s", st)
	}
	if read("out.txt") != "changed-in-vm" {
		t.Errorf("the agent's change did not come back from the guest: %q", read("out.txt"))
	}
	if read("README.md") != "# demo" {
		t.Errorf("the project did not reach the guest: %q", read("README.md"))
	}
	if _, err := os.Stat(filepath.Join(work, ".env")); err == nil {
		t.Error("the secret went into the guest and came back")
	}
	net := read("net.txt")
	for _, want := range []string{"pastebin=403", "direct=blocked", "sudo=no"} {
		if !strings.Contains(net, want) {
			t.Errorf("net.txt lacks %q:\n%s", want, net)
		}
	}
	noVMLeft(t)
}

// TestVMBox_StopBringsTheWorkBack stops `ovara box -vm` with SIGTERM while
// the agent runs: the agent gets SIGTERM in the guest (every process of
// its user), what it wrote until then still comes back, and the VM goes.
func TestVMBox_StopBringsTheWorkBack(t *testing.T) {
	bin, dir, project := vmE2E(t)
	script := strings.Join([]string{
		"echo before-stop > before.txt",
		"trap 'echo got-term > term.txt; exit 3' TERM",
		"echo agent-$((1+1))-ready >&2", // only running it prints agent-2-ready
		"while :; do sleep 1; done",
	}, "\n")
	cmd := exec.Command(bin, "box", "-vm", "netns-test", "-dir", dir, "-ui", "off", "-no-commit-back", "-keep", project, "--", "sh", "-c", script) //nolint:gosec // the binary under test
	cmd.Env = append(os.Environ(), "OVARA_BOX_VM_NETNS_TEST=1")
	var out syncBuffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Minute)
	for !strings.Contains(out.String(), "agent-2-ready") {
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatalf("the agent never started:\n%s", out.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	select {
	case <-waited:
	case <-time.After(2 * time.Minute):
		_ = cmd.Process.Kill()
		t.Fatalf("ovara box did not stop:\n%s", out.String())
	}
	log := out.String()
	for _, want := range []string{"stopping the agent", "agent exited with status 3"} {
		if !strings.Contains(log, want) {
			t.Errorf("output lacks %q:\n%s", want, log)
		}
	}
	work := keptWorkspace(t, dir, log)
	for name, want := range map[string]string{"before.txt": "before-stop", "term.txt": "got-term"} {
		b, _ := os.ReadFile(filepath.Join(work, name)) //nolint:gosec // test output
		if got := strings.TrimSpace(string(b)); got != want {
			t.Errorf("%s = %q after the stop, want %q (the guest's work did not come back)\n%s", name, got, want, log)
		}
	}
	noVMLeft(t)
}

// syncBuffer is a bytes.Buffer safe for a writer and a reader at once.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// vmE2E checks what the end-to-end VM tests need and returns the ovara
// binary, a deployment directory and a project (a git repository with a
// README.md committed and an untracked .env).
func vmE2E(t *testing.T) (bin, dir, project string) {
	t.Helper()
	skip := t.Skipf
	if os.Getenv("OVARA_REQUIRE_VM_E2E") == "1" {
		skip = t.Fatalf
	}
	bin = os.Getenv("OVARA_TEST_BINARY")
	if bin == "" {
		skip("set OVARA_TEST_BINARY to a built ovara")
	}
	if os.Geteuid() != 0 {
		skip("needs root")
	}
	for _, tool := range []string{"ip", "nft", "git", "curl", "useradd"} {
		if _, err := exec.LookPath(tool); err != nil {
			skip("needs %s", tool)
		}
	}
	t.Cleanup(func() { _ = exec.Command("userdel", "-r", boxDefaultUser).Run() }) //nolint:gosec // the box's own default user

	base := t.TempDir()
	dir = filepath.Join(base, "deploy")
	project = filepath.Join(base, "project")
	if err := os.Mkdir(project, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"README.md": "# demo\n", ".env": "SECRET=hunter2\n"} {
		if err := os.WriteFile(filepath.Join(project, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", project, "-c", "user.name=t", "-c", "user.email=t@t"}, args...)...) //nolint:gosec // fixed test commands
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q", "-b", "main")
	git("add", "README.md")
	git("commit", "-qm", "init")
	return bin, dir, project
}

// keptWorkspace is the one workspace a -keep run left in dir.
func keptWorkspace(t *testing.T, dir, log string) string {
	t.Helper()
	runs, _ := filepath.Glob(filepath.Join(dir, "runs", "*", "work"))
	if len(runs) != 1 {
		t.Fatalf("want one kept workspace, found %v\n%s", runs, log)
	}
	return runs[0]
}

// noVMLeft fails when the stand-in VM's namespace is still on the host.
func noVMLeft(t *testing.T) {
	t.Helper()
	if out, _ := exec.Command("ip", "netns", "list").CombinedOutput(); strings.Contains(string(out), "ovara-box-") {
		t.Errorf("the VM's namespace was left behind:\n%s", out)
	}
}
