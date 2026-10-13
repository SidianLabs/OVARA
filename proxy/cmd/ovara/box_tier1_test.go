//go:build linux

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"ovara.proxy/internal/boxgate"
)

// The tier 1 tests run box-init from this test binary.
func TestMain(m *testing.M) {
	if os.Getenv("OVARA_TEST_BOXINIT") == "1" && len(os.Args) > 1 && os.Args[1] == "box-init" {
		if err := cmdBoxInit(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

const testAgentID = 65534 // nobody

// tier1Fixture is a run directory as `ovara box` lays it out, a host
// "project" outside it, and a file under /root.
type tier1Fixture struct {
	runDir, work, home, ca, project, rootFile, token string
}

func newTier1Fixture(t *testing.T) *tier1Fixture {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root (namespaces, mounts, another user)")
	}
	base, err := os.MkdirTemp("/var/tmp", "ovara-t1-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	f := &tier1Fixture{runDir: filepath.Join(base, "run"), token: "tok-" + strconv.FormatInt(time.Now().UnixNano(), 36)}
	f.work, f.home, f.ca = filepath.Join(f.runDir, "work"), filepath.Join(f.runDir, "home"), filepath.Join(f.runDir, "ovara-ca.pem")
	for _, d := range []string{f.runDir, f.work, f.home} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{f.work, f.home} {
		if err := os.Chown(d, testAgentID, testAgentID); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(f.work, "hello.txt"), []byte("workspace"), 0o644); err != nil { //nolint:gosec // world-readable on purpose: only the box may keep the agent out
		t.Fatal(err)
	}
	if err := os.WriteFile(f.ca, []byte("PUBLIC CERT"), 0o644); err != nil { //nolint:gosec // world-readable on purpose: only the box may keep the agent out
		t.Fatal(err)
	}
	// the original project: world-readable, so only the box keeps it out
	proj, err := os.MkdirTemp("/srv", "ovara-t1-project-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(proj) })
	if err := os.Chmod(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	f.project = filepath.Join(proj, ".env")
	if err := os.WriteFile(f.project, []byte("API_KEY=real"), 0o644); err != nil { //nolint:gosec // world-readable on purpose: only the box may keep the agent out
		t.Fatal(err)
	}
	rf, err := os.CreateTemp("/root", "ovara-t1-")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = rf.WriteString("root's")
	rf.Close()
	f.rootFile = rf.Name()
	t.Cleanup(func() { os.Remove(f.rootFile) })
	return f
}

const tier1Probe = `r() { echo "$1=$2"; }
cat "$P_PROJECT" >/dev/null 2>&1 && r PROJECT readable || r PROJECT absent
cat "$P_ROOT" >/dev/null 2>&1 && r ROOTFILE readable || r ROOTFILE absent
r WORK "$(cat hello.txt)"
echo x > new.txt && r WORKWRITE ok || r WORKWRITE refused
r CA "$(cat "$P_CA")"
(echo x > "$P_CA") 2>/dev/null && r CAWRITE ok || r CAWRITE refused
[ -x /usr/bin/env ] && r USRBIN ok || r USRBIN missing
(touch /usr/ovara-probe) 2>/dev/null && r USRWRITE ok || r USRWRITE refused
r SHADOW "$( [ -s /etc/shadow ] && echo present || echo covered)"
r SSHDIR "$(ls -A /etc/ssh 2>/dev/null | wc -l)"
r IFACES "$(awk -F: 'NR>2{gsub(/ /,"",$1); printf "%s ", $1}' /proc/net/dev)"
r HOMES "$(ls /home 2>/dev/null | wc -l)"
r SRV "$( [ -e /srv ] && echo present || echo absent)"
r UID "$(awk '/^Uid/{print $2}' /proc/self/status)"
r NNP "$(awk '/^NoNewPrivs/{print $2}' /proc/self/status)"
r PROC1 "$( [ -e /proc/1/cmdline ] && echo visible || echo hidden)"
r TMP "$(ls -A /tmp | wc -l)"
id >/dev/null 2>&1; r GATE $?
sleep 0.5
r DONE yes
`

// runTier1Box runs the probe through box-init -tier1 and returns its
// output as NAME=value pairs, the execs the gate was asked about, and every
// command line seen on the host while it ran.
func runTier1Box(t *testing.T, f *tier1Fixture, isolated bool, netns string) (map[string]string, []boxgate.Exec, string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	spec := tier1Spec{
		Netns: netns, UID: testAgentID, GID: testAgentID, Dir: f.work,
		Argv: []string{"/bin/sh", "-c", tier1Probe},
		Env: []string{
			"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=" + f.home,
			"P_PROJECT=" + f.project, "P_ROOT=" + f.rootFile, "P_CA=" + f.ca,
			"HTTPS_PROXY=http://agent:" + f.token + "@10.200.1.1:9443",
		},
	}
	if isolated {
		spec.Root = filepath.Join(f.runDir, "root")
		if err := os.Mkdir(spec.Root, 0o700); err != nil {
			t.Fatal(err)
		}
		spec.Binds = []tier1Bind{{Src: f.work, Dst: f.work, RW: true}, {Src: f.home, Dst: f.home, RW: true}, {Src: f.ca, Dst: f.ca}}
	}
	cmd, done, err := tier1Command(self, spec)
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	cmd.Env = append(cmd.Env, "OVARA_TEST_BOXINIT=1")
	out, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	cmd.Stdout, cmd.Stderr = out, out

	// every command line on the host while the box runs
	var mu sync.Mutex
	var cmdlines strings.Builder
	stop := make(chan struct{})
	scanned := make(chan struct{})
	go func() {
		defer close(scanned)
		for {
			ents, _ := os.ReadDir("/proc")
			for _, e := range ents {
				if b, err := os.ReadFile("/proc/" + e.Name() + "/cmdline"); err == nil {
					mu.Lock()
					cmdlines.Write(bytes.ReplaceAll(b, []byte{0}, []byte{' '}))
					cmdlines.WriteByte('\n')
					mu.Unlock()
				}
			}
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
	}()
	var seen []boxgate.Exec
	g := &commandGate{}
	tr := &boxgate.Tracer{Skip: g.skip, Decide: func(e boxgate.Exec) boxgate.Verdict {
		seen = append(seen, e)
		if filepath.Base(e.Exe) == "id" {
			return boxgate.Deny
		}
		return boxgate.Allow
	}}
	code, err := tr.Run(cmd)
	close(stop)
	<-scanned
	b, _ := os.ReadFile(out.Name())
	if err != nil || code != 0 {
		t.Fatalf("box exit %d, %v\n%s", code, err, b)
	}
	got := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			got[k] = v
		}
	}
	if got["DONE"] != "yes" {
		t.Fatalf("the probe did not finish:\n%s", b)
	}
	return got, seen, cmdlines.String()
}

func want(t *testing.T, got map[string]string, k, v string) {
	t.Helper()
	if got[k] != v {
		t.Errorf("%s = %q, want %q", k, got[k], v)
	}
}

// Tier 1's own root: the workspace, home and CA are there; the original
// project, /root, /home and /srv are not; the system is read-only and
// /etc/shadow empty. The command gate still sees every exec, starting with
// the agent (box-init itself is not asked about), and the proxy token is on
// no command line.
func TestTier1IsolatedFileSystem(t *testing.T) {
	f := newTier1Fixture(t)
	netns := ""
	if _, err := exec.LookPath("ip"); err == nil {
		netns = "ovara-t1-" + strconv.Itoa(os.Getpid())
		if out, err := exec.Command("ip", "netns", "add", netns).CombinedOutput(); err != nil {
			t.Fatalf("ip netns add: %v %s", err, out)
		}
		t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", netns).Run() })
	}
	got, seen, cmdlines := runTier1Box(t, f, true, netns)
	want(t, got, "PROJECT", "absent")
	want(t, got, "ROOTFILE", "absent")
	want(t, got, "WORK", "workspace")
	want(t, got, "WORKWRITE", "ok")
	want(t, got, "CA", "PUBLIC CERT")
	want(t, got, "CAWRITE", "refused")
	want(t, got, "USRBIN", "ok")
	want(t, got, "USRWRITE", "refused")
	want(t, got, "SHADOW", "covered")
	want(t, got, "SSHDIR", "0")
	if netns != "" {
		want(t, got, "IFACES", "lo ")
	}
	want(t, got, "HOMES", "0")
	want(t, got, "SRV", "absent")
	want(t, got, "UID", strconv.Itoa(testAgentID))
	want(t, got, "NNP", "1")
	want(t, got, "PROC1", "hidden")
	want(t, got, "TMP", "0")
	want(t, got, "GATE", "137") // refused by the gate: killed before it ran
	if len(seen) == 0 || seen[0].Argv[0] != "/bin/sh" {
		t.Errorf("the first exec the gate decided was not the agent: %+v", seen)
	}
	if strings.Contains(cmdlines, f.token) {
		t.Error("the proxy token was on a command line")
	}
	if !strings.Contains(cmdlines, "box-init -tier1") {
		t.Error("the scan never saw box-init (it proves nothing)")
	}
	if _, err := os.Stat(filepath.Join(f.work, "new.txt")); err != nil {
		t.Error("the agent's write to the workspace is not on the host")
	}
	if ents, _ := os.ReadDir(filepath.Join(f.runDir, "root")); len(ents) != 0 {
		t.Errorf("the box's root left %d entries on the host", len(ents))
	}
}

// -tier1-fs host is the old behaviour: the same probe reads the project.
// It is the control for the test above.
func TestTier1HostFileSystem(t *testing.T) {
	f := newTier1Fixture(t)
	got, _, cmdlines := runTier1Box(t, f, false, "")
	want(t, got, "PROJECT", "readable")
	want(t, got, "SHADOW", "present")
	want(t, got, "WORK", "workspace")
	want(t, got, "NNP", "1")
	want(t, got, "UID", strconv.Itoa(testAgentID))
	want(t, got, "GATE", "137")
	if strings.Contains(cmdlines, f.token) {
		t.Error("the proxy token was on a command line")
	}
}

// A tier 1 -mount may add a place, not cover the box's own system.
func TestCheckMountsTier1(t *testing.T) {
	tools := t.TempDir()
	ovaraDir := t.TempDir()
	for _, dst := range []string{"/opt/tools", "/tmp/tools", "/srv/x"} {
		if err := checkMountsFor([]string{tools + ":" + dst}, ovaraDir, tier1DstRefused); err != nil {
			t.Errorf("%s refused: %v", dst, err)
		}
	}
	for _, dst := range []string{"/usr/local/x", "/etc", "/dev/x", "/proc", "/tmp", "/var/lib/ovara/runs/r/work", "/var/lib", "/"} {
		if err := checkMountsFor([]string{tools + ":" + dst}, ovaraDir, tier1DstRefused); err == nil {
			t.Errorf("%s accepted", dst)
		}
	}
}

func TestMountpointNoFollow(t *testing.T) {
	root := t.TempDir()
	if err := os.Symlink("/", filepath.Join(root, "bin")); err != nil {
		t.Fatal(err)
	}
	if err := mountpointNoFollow(root, "/bin/x", true); err == nil {
		t.Error("a mount point through a symlink was made")
	}
	if err := mountpointNoFollow(root, "/opt/tools/a.txt", false); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(filepath.Join(root, "opt/tools/a.txt")); err != nil || !st.Mode().IsRegular() {
		t.Errorf("file mount point: %v", err)
	}
	if err := mountpointNoFollow(root, "/", true); err == nil {
		t.Error("the root itself was accepted")
	}
	if got := unescapeMountinfo(`/a\040b\134c`); got != `/a b\c` {
		t.Errorf("unescape: %q", got)
	}
}

// A kernel that cannot mount /proc with hidepid=invisible (before 5.8)
// makes an isolated tier 1 box refuse to start, unless the person accepts
// a /proc that shows the host's processes (-allow-visible-procs).
func TestTier1RefusesAProcThatShowsTheHostsProcesses(t *testing.T) {
	var tried []string
	oldKernel := func(opts string) error {
		tried = append(tried, opts)
		if opts != "" {
			return errors.New("invalid argument")
		}
		return nil
	}
	err := mountBoxProc(oldKernel, false)
	if !errors.Is(err, errVisibleProcs) || !strings.Contains(err.Error(), "-allow-visible-procs") {
		t.Fatalf("old kernel without -allow-visible-procs: %v", err)
	}
	if len(tried) != 1 {
		t.Fatalf("a plain /proc was mounted anyway: %q", tried)
	}
	tried = nil
	if err := mountBoxProc(oldKernel, true); err != nil || len(tried) != 2 || tried[1] != "" {
		t.Fatalf("with -allow-visible-procs: %v %q", err, tried)
	}
	tried = nil
	newKernel := func(opts string) error { tried = append(tried, opts); return nil }
	if err := mountBoxProc(newKernel, false); err != nil || len(tried) != 1 || tried[0] != "hidepid=invisible" {
		t.Fatalf("new kernel: %v %q", err, tried)
	}
}
