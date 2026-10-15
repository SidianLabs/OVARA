package vm

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func testSpec() Spec {
	return Spec{Name: "ovara-test-1", CPUs: 2, MemoryGiB: 4, DiskGiB: 20, ProxyPort: 9443, GatePort: 9444}
}

// The instance config turns off, explicitly, every Lima default that would
// let the guest see or reach the host, and carries the lockdown.
func TestLimaConfig_Hardened(t *testing.T) {
	raw, err := (&Lima{}).Config(testSpec())
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("config is not JSON (Lima reads it as YAML): %v", err)
	}
	if m, ok := c["mounts"].([]any); !ok || len(m) != 0 {
		t.Errorf("mounts = %v, want none (the workspace is copied in)", c["mounts"])
	}
	ssh := c["ssh"].(map[string]any)
	for _, k := range []string{"forwardAgent", "forwardX11", "loadDotSSHPubKeys"} {
		if ssh[k] != false {
			t.Errorf("ssh.%s = %v, want false", k, ssh[k])
		}
	}
	if c["propagateProxyEnv"] != false {
		t.Errorf("propagateProxyEnv = %v, want false", c["propagateProxyEnv"])
	}
	cd := c["containerd"].(map[string]any)
	if cd["system"] != false || cd["user"] != false {
		t.Errorf("containerd = %v, want both off", cd)
	}
	pf := c["portForwards"].([]any)
	if len(pf) != 2 {
		t.Fatalf("portForwards = %v, want two ignore-all rules", pf)
	}
	for _, r := range pf {
		r := r.(map[string]any)
		rng := r["guestPortRange"].([]any)
		if r["ignore"] != true || rng[0] != float64(1) || rng[1] != float64(65535) {
			t.Errorf("port forward %v does not ignore every port", r)
		}
	}
	prov := c["provision"].([]any)[0].(map[string]any)
	script := prov["script"].(string)
	if prov["mode"] != "system" {
		t.Errorf("provision mode %v, want system (root)", prov["mode"])
	}
	for _, want := range []string{
		"table inet " + lockdownTable,
		"policy drop",
		"ip daddr ${HOST_IP} tcp dport { 9443, 9444 } accept",
		"udp dport 53 drop",
		"getent ahostsv4 " + limaHost,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("provision script lacks %q:\n%s", want, script)
		}
	}
	images := c["images"].([]any)
	arches := map[string]bool{}
	for _, im := range images {
		arches[im.(map[string]any)["arch"].(string)] = true
	}
	if !arches["x86_64"] || !arches["aarch64"] {
		t.Errorf("images cover %v, want x86_64 and aarch64", arches)
	}
}

func TestSpecValidate(t *testing.T) {
	bad := []Spec{
		{Name: "myvm", CPUs: 2, MemoryGiB: 4, DiskGiB: 20, ProxyPort: 1, GatePort: 2},          // not ovara-
		{Name: "ovara-X", CPUs: 2, MemoryGiB: 4, DiskGiB: 20, ProxyPort: 1, GatePort: 2},       // upper case
		{Name: "ovara-a;rm", CPUs: 2, MemoryGiB: 4, DiskGiB: 20, ProxyPort: 1, GatePort: 2},    // punctuation
		{Name: "ovara-a", CPUs: 0, MemoryGiB: 4, DiskGiB: 20, ProxyPort: 1, GatePort: 2},       // no cpu
		{Name: "ovara-a", CPUs: 2, MemoryGiB: 4, DiskGiB: 2, ProxyPort: 1, GatePort: 2},        // tiny disk
		{Name: "ovara-a", CPUs: 2, MemoryGiB: 4, DiskGiB: 20, ProxyPort: 0, GatePort: 2},       // bad port
		{Name: "ovara-a", CPUs: 2, MemoryGiB: 4, DiskGiB: 20, ProxyPort: 9443, GatePort: 9443}, // same port
	}
	for _, s := range bad {
		if err := s.Validate(); err == nil {
			t.Errorf("accepted %+v", s)
		}
	}
	if err := testSpec().Validate(); err != nil {
		t.Errorf("rejected a good spec: %v", err)
	}
}

// probe outcomes for the stand-in's egress check
const (
	probeBlocked = "echo BLOCKED; exit 0" // the lockdown holds
	probeOpen    = "echo OPEN; exit 0"    // a direct connection got out
	probeBroken  = "exit 127"             // the probe could not run at all
)

// fakeLimactl writes a limactl stand-in that logs every call and answers
// the lockdown checks as told: nftOK loads the table; probe is what the
// egress check reports.
func fakeLimactl(t *testing.T, nftOK bool, probe string) (bin, log string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in is a shell script")
	}
	dir := t.TempDir()
	log = filepath.Join(dir, "calls.log")
	nft := "exit 1"
	if nftOK {
		nft = "echo 'table inet ovara_vm { chain output { type filter hook output priority 0; policy drop; } }'; exit 0"
	}
	script := "#!/bin/sh\n" +
		"echo \"$*\" >> " + log + "\n" +
		"case \"$*\" in\n" +
		"  *'nft list table'*) " + nft + " ;;\n" +
		"  *'/dev/tcp/1.1.1.1/443'*) " + probe + " ;;\n" +
		"  *'exit-seven'*) exit 7 ;;\n" +
		"esac\n" +
		"exit 0\n"
	bin = filepath.Join(dir, "limactl")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil { //nolint:gosec // a test stand-in that must be executable
		t.Fatal(err)
	}
	return bin, log
}

func calls(t *testing.T, log string) []string {
	t.Helper()
	b, err := os.ReadFile(log) //nolint:gosec // the test's own log
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func TestLima_CreateWritesConfigAndStarts(t *testing.T) {
	bin, log := fakeLimactl(t, true, probeBlocked)
	l := &Lima{Limactl: bin, Dir: t.TempDir()}
	if err := l.Create(context.Background(), testSpec()); err != nil {
		t.Fatal(err)
	}
	got := calls(t, log)
	if len(got) != 2 || !strings.HasPrefix(got[0], "create --tty=false --name=ovara-test-1 ") || got[1] != "start --tty=false ovara-test-1" {
		t.Fatalf("calls %q, want create then start", got)
	}
	cfg := strings.TrimPrefix(got[0], "create --tty=false --name=ovara-test-1 ")
	st, err := os.Stat(cfg)
	if err != nil {
		t.Fatalf("config not written: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("config mode %v, want 0600", st.Mode().Perm())
	}
}

// Verify is the gate before any agent runs: the lockdown must be loaded and
// a direct connection out must fail. Every other outcome is a refusal.
func TestLima_VerifyFailsClosed(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name    string
		nftOK   bool
		probe   string
		wantErr bool
	}{
		{"lockdown holds", true, probeBlocked, false},
		{"table missing", false, probeBlocked, true},
		{"direct egress works", true, probeOpen, true},
		{"probe could not run", true, probeBroken, true},
	} {
		bin, _ := fakeLimactl(t, c.nftOK, c.probe)
		err := (&Lima{Limactl: bin}).Verify(ctx, "ovara-test-1")
		if (err != nil) != c.wantErr {
			t.Errorf("%s: Verify = %v, want error %v", c.name, err, c.wantErr)
		}
	}
}

func TestLima_RunReturnsTheGuestStatus(t *testing.T) {
	bin, log := fakeLimactl(t, true, probeBlocked)
	code, err := (&Lima{Limactl: bin}).Run(context.Background(), "ovara-test-1", []string{"sh", "-c", "exit-seven"}, Stdio{})
	if err != nil || code != 7 {
		t.Fatalf("Run = %d, %v; want 7, nil", code, err)
	}
	if got := calls(t, log); got[0] != "shell --workdir=/ ovara-test-1 -- sh -c exit-seven" {
		t.Fatalf("call %q", got[0])
	}
}

func TestLima_CopyDirections(t *testing.T) {
	bin, log := fakeLimactl(t, true, probeBlocked)
	l := &Lima{Limactl: bin}
	ctx := context.Background()
	if err := l.CopyIn(ctx, "ovara-test-1", "/host/ws", "/work"); err != nil {
		t.Fatal(err)
	}
	if err := l.CopyOut(ctx, "ovara-test-1", "/work", "/host/out"); err != nil {
		t.Fatal(err)
	}
	got := calls(t, log)
	if got[0] != "copy -r /host/ws ovara-test-1:/work" || got[1] != "copy -r ovara-test-1:/work /host/out" {
		t.Fatalf("calls %q", got)
	}
}

// Every method refuses a VM Ovara did not create, before calling limactl.
func TestLima_RefusesForeignVMs(t *testing.T) {
	bin, log := fakeLimactl(t, true, probeBlocked)
	l := &Lima{Limactl: bin}
	ctx := context.Background()
	if err := l.Verify(ctx, "default"); err == nil {
		t.Error("Verify accepted a foreign VM")
	}
	if err := l.CopyIn(ctx, "default", "/a", "/b"); err == nil {
		t.Error("CopyIn accepted a foreign VM")
	}
	if err := l.CopyOut(ctx, "default", "/a", "/b"); err == nil {
		t.Error("CopyOut accepted a foreign VM")
	}
	if _, err := l.Run(ctx, "default", []string{"true"}, Stdio{}); err == nil {
		t.Error("Run accepted a foreign VM")
	}
	if err := l.Delete(ctx, "default"); err == nil {
		t.Error("Delete accepted a foreign VM")
	}
	if _, err := os.Stat(log); err == nil {
		t.Errorf("limactl was called for a foreign VM: %v", calls(t, log))
	}
}
