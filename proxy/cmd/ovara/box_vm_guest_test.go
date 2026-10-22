//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// writeTree keeps links as links (never reading through them, so a link to
// /dev/zero costs nothing) and leaves FIFOs out instead of hanging on them.
func TestWriteTree_LinksAndSpecialFiles(t *testing.T) {
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "d", "f.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{"zero": "/dev/zero", "pw": "/etc/passwd"} {
		if err := os.Symlink(target, filepath.Join(src, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := syscall.Mkfifo(filepath.Join(src, "pipe"), 0o644); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- writeTree(src, &buf, treeMaxBytes, treeMaxEntries) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("writeTree hung (read through a link or a FIFO)")
	}
	out := filepath.Join(t.TempDir(), "ws")
	if err := extractTree(&buf, out, treeMaxBytes, treeMaxEntries); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(out, "d", "f.txt")); string(b) != "hello" {
		t.Errorf("d/f.txt = %q", b)
	}
	for name, target := range map[string]string{"zero": "/dev/zero", "pw": "/etc/passwd"} {
		if got, err := os.Readlink(filepath.Join(out, name)); err != nil || got != target {
			t.Errorf("%s: link %q, %v; want a link to %s", name, got, err, target)
		}
	}
	if _, err := os.Lstat(filepath.Join(out, "pipe")); err == nil {
		t.Error("the FIFO came back")
	}
}

// The guest side end to end, with this machine as the guest and a TCP gate
// in the test as the host: the agent runs as a fresh unprivileged user under
// no_new_privs and the box's seccomp filter, every program it starts goes to
// the gate, a refused one never runs, the spec (and its token) is gone
// before the agent starts, and the workspace comes back as a tar.
func TestVMGuest_RunsTheAgentBehindTheGate(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (a user of its own, credentials)")
	}
	if _, err := exec.LookPath("useradd"); err != nil {
		t.Skip("needs useradd")
	}
	const agentUser = "ovara-vmtest"
	t.Cleanup(func() { _ = exec.Command("userdel", "-r", agentUser).Run() }) //nolint:gosec // fixed test user

	base, err := os.MkdirTemp("/var/tmp", "ovara-vmg-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	// the agent's user runs the shim, so the binary must be where it can
	bin := filepath.Join(base, "ovara")
	self, _ := os.Executable()
	data, err := os.ReadFile(self) //nolint:gosec // this test binary
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, data, 0o755); err != nil { //nolint:gosec // must be executable by the agent
		t.Fatal(err)
	}
	// the workspace arrives as a tar, as `ovara box` sends it
	src := filepath.Join(base, "src")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "README"), []byte("project\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	treeIn := filepath.Join(base, "tree-in.tar")
	if err := writeTreeFile(src, treeIn); err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(base, "work")

	token, _ := newGateToken()
	addr, asked, gateDone := startGate(t, token)

	script := `id -u > uid.txt
grep -E '^(Seccomp|NoNewPrivs):' /proc/self/status > status.txt
touch denied-marker
echo changed > out.txt
exit 3`
	spec := vmGuestSpec{
		Argv: []string{"sh", "-c", script},
		Env:  []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/home/" + agentUser, "OVARA_TEST_BOXINIT=1"},
		Dir:  work, User: agentUser,
		Gate: true, GateAddr: addr, GateToken: token,
		TreeIn: treeIn, TreeOut: filepath.Join(base, "tree.tar"),
	}
	specPath := filepath.Join(base, "spec.json")
	sb, _ := json.Marshal(spec)
	if err := os.WriteFile(specPath, sb, 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(bin, "box-init", "-vm", specPath) //nolint:gosec // the test binary standing in for ovara
	cmd.Env = []string{"OVARA_TEST_BOXINIT=1", "PATH=/usr/local/bin:/usr/bin:/bin"}
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if err != nil && !errorsAs(err, &ee) {
		t.Fatalf("box-init -vm: %v\n%s", err, out)
	}
	if code := cmd.ProcessState.ExitCode(); code != 3 {
		t.Fatalf("exit status %d, want the agent's 3\n%s", code, out)
	}
	<-gateDone

	if _, err := os.Stat(specPath); err == nil {
		t.Error("the spec (with the gate token) was left in the guest")
	}
	if _, err := os.Stat(treeIn); err == nil {
		t.Error("the incoming workspace tar was left in the guest")
	}
	tf, err := os.Open(spec.TreeOut)
	if err != nil {
		t.Fatalf("no workspace tar: %v\n%s", err, out)
	}
	defer tf.Close()
	back := filepath.Join(base, "back")
	if err := extractTree(tf, back, treeMaxBytes, treeMaxEntries); err != nil {
		t.Fatal(err)
	}
	read := func(name string) string {
		b, _ := os.ReadFile(filepath.Join(back, name)) //nolint:gosec // test output
		return strings.TrimSpace(string(b))
	}
	uid, err := strconv.Atoi(read("uid.txt"))
	if err != nil || uid == 0 {
		t.Errorf("the agent ran as uid %q, want a non-root user", read("uid.txt"))
	}
	if st := read("status.txt"); !strings.Contains(st, "NoNewPrivs:\t1") || !strings.Contains(st, "Seccomp:\t2") {
		t.Errorf("the agent's process is not under no_new_privs and a seccomp filter:\n%s", st)
	}
	if read("README") != "project" {
		t.Errorf("the workspace that went in did not come back: %q", read("README"))
	}
	if read("out.txt") != "changed" {
		t.Errorf("the agent's change did not come back: %q", read("out.txt"))
	}
	if _, err := os.Stat(filepath.Join(back, "denied-marker")); err == nil {
		t.Error("a program the gate refused ran")
	}
	got := strings.Join(asked(), "\n")
	for _, want := range []string{"id -u", "touch denied-marker"} {
		if !strings.Contains(got, want) {
			t.Errorf("the gate was not asked about %q; it saw:\n%s", want, got)
		}
	}
	if strings.Contains(got, "box-init") {
		t.Errorf("the gate was asked about Ovara's own shim:\n%s", got)
	}
}

// Without the run's token box-init does not start the agent at all.
func TestVMGuest_RefusesToStartWithoutTheGate(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	base := t.TempDir()
	src := filepath.Join(base, "src")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatal(err)
	}
	treeIn := filepath.Join(base, "tree-in.tar")
	if err := writeTreeFile(src, treeIn); err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(base, "work")
	token, _ := newGateToken()
	addr, _, _ := startGate(t, token)
	wrong, _ := newGateToken()
	spec := vmGuestSpec{
		Argv: []string{"sh", "-c", "touch " + filepath.Join(work, "ran")},
		Dir:  work, User: "ovara-vmtest-nogate",
		Gate: true, GateAddr: addr, GateToken: wrong,
		TreeIn: treeIn, TreeOut: filepath.Join(base, "tree.tar"),
	}
	t.Cleanup(func() { _ = exec.Command("userdel", "-r", spec.User).Run() }) //nolint:gosec // fixed test user
	specPath := filepath.Join(base, "spec.json")
	sb, _ := json.Marshal(spec)
	if err := os.WriteFile(specPath, sb, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := runVMGuest(specPath)
	if err == nil || !strings.Contains(err.Error(), "refusing to start the agent") {
		t.Fatalf("err = %v, want a refusal", err)
	}
	if _, err := os.Stat(filepath.Join(work, "ran")); err == nil {
		t.Fatal("the agent ran without the gate")
	}
}

func errorsAs(err error, target **exec.ExitError) bool {
	e, ok := err.(*exec.ExitError) //nolint:errorlint // exec returns it unwrapped
	if ok {
		*target = e
	}
	return ok
}

var _ = io.EOF

// procHasUID decides which processes a stop signals: it must match this
// process by its own uid and nothing else.
func TestProcHasUID(t *testing.T) {
	me := os.Getpid()
	if !procHasUID(me, os.Getuid()) {
		t.Errorf("procHasUID(self, %d) = false", os.Getuid())
	}
	if procHasUID(me, os.Getuid()+12345) {
		t.Error("procHasUID matched another uid")
	}
	if procHasUID(1<<30, os.Getuid()) {
		t.Error("procHasUID matched a process that does not exist")
	}
}
