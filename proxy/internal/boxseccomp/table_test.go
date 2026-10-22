//go:build linux

package boxseccomp

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

// An independent source of call numbers: x/sys' generated tables, read as
// text so a build for one architecture can check the other's numbers.

var (
	nrOnce sync.Once
	nrTab  map[string]map[string]uint32 // arch -> upper-case call name -> number
	nrErr  error
)

func xsysNumbers(t testing.TB, arch string) map[string]uint32 {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go tool to locate golang.org/x/sys")
	}
	nrOnce.Do(func() {
		out, err := exec.Command("go", "list", "-f", "{{.Dir}}", "golang.org/x/sys/unix").Output()
		if err != nil {
			nrErr = fmt.Errorf("go list golang.org/x/sys/unix: %w", err)
			return
		}
		dir := strings.TrimSpace(string(out))
		re := regexp.MustCompile(`^\s*SYS_([A-Z0-9_]+)\s*=\s*(\d+)`)
		nrTab = map[string]map[string]uint32{}
		for _, a := range []string{"amd64", "arm64"} {
			f, err := os.Open(filepath.Join(dir, "zsysnum_linux_"+a+".go"))
			if err != nil {
				nrErr = err
				return
			}
			m := map[string]uint32{}
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				if g := re.FindStringSubmatch(sc.Text()); g != nil {
					n, _ := strconv.ParseUint(g[2], 10, 32)
					m[g[1]] = uint32(n)
				}
			}
			f.Close()
			nrTab[a] = m
		}
	})
	if nrErr != nil {
		t.Fatal(nrErr)
	}
	return nrTab[arch]
}

func archOf(name string) Arch {
	if name == "amd64" {
		return Amd64
	}
	return Arm64
}

var bothArches = []string{"amd64", "arm64"}

// notInXSys: calls newer than the pinned x/sys. Their numbers are the
// kernel's, identical on both architectures (asm-generic, 427 and up), and
// this list is the only place a table entry may lack an x/sys name.
var notInXSys = map[string]uint32{"open_tree_attr": 467}

// TestTableMatchesXSys checks every number in Table against x/sys for both
// architectures: the same call under each name, no duplicates, nothing in the
// x32 range, and the arm64 gaps explicit rather than a stray 0.
func TestTableMatchesXSys(t *testing.T) {
	names := map[string]bool{}
	for _, r := range Table {
		if names[r.Name] {
			t.Errorf("duplicate rule %s", r.Name)
		}
		names[r.Name] = true
		if r.Errno == 0 || r.Group == "" {
			t.Errorf("%s: errno or group missing", r.Name)
		}
		if r.Amd64 == NoNr && r.Arm64 == NoNr {
			t.Errorf("%s exists on no architecture", r.Name)
		}
		for _, an := range bothArches {
			got := archOf(an).nr(r)
			want, ok := xsysNumbers(t, an)[strings.ToUpper(r.Name)]
			if n, newer := notInXSys[r.Name]; newer && !ok {
				if got != n {
					t.Errorf("%s: %s number %d, the kernel's is %d", r.Name, an, got, n)
				}
				continue
			}
			switch {
			case !ok && got != NoNr:
				t.Errorf("%s: Table has %d on %s but x/sys has no such call", r.Name, got, an)
			case ok && got == NoNr:
				t.Errorf("%s: x/sys has %d on %s but Table says there is none", r.Name, want, an)
			case ok && got != want:
				t.Errorf("%s: %s number %d, x/sys says %d", r.Name, an, got, want)
			}
		}
	}
	for _, an := range bothArches {
		if _, err := Build(archOf(an), Table); err != nil { // duplicate numbers, x32 range, jump sizes
			t.Errorf("%s: %v", an, err)
		}
	}
}

// The values the table compares arguments with, against x/sys.
func TestTableConstantsMatchXSys(t *testing.T) {
	for name, pair := range map[string][2]uint64{
		"CLONE_NEWNS": {cloneNewNS, unix.CLONE_NEWNS}, "CLONE_NEWCGROUP": {cloneNewCgroup, unix.CLONE_NEWCGROUP},
		"CLONE_NEWUTS": {cloneNewUTS, unix.CLONE_NEWUTS}, "CLONE_NEWIPC": {cloneNewIPC, unix.CLONE_NEWIPC},
		"CLONE_NEWUSER": {cloneNewUser, unix.CLONE_NEWUSER}, "CLONE_NEWPID": {cloneNewPID, unix.CLONE_NEWPID},
		"CLONE_NEWNET": {cloneNewNet, unix.CLONE_NEWNET}, "CLONE_NEWTIME": {cloneNewTime, unix.CLONE_NEWTIME},
		"AF_KEY": {afKey, unix.AF_KEY}, "AF_NETLINK": {afNetlink, unix.AF_NETLINK}, "AF_PACKET": {afPacket, unix.AF_PACKET},
		"AF_RDS": {afRds, unix.AF_RDS}, "AF_TIPC": {afTipc, unix.AF_TIPC}, "AF_ALG": {afAlg, unix.AF_ALG}, "AF_VSOCK": {afVsock, unix.AF_VSOCK},
		"NETLINK_XFRM": {nlXfrm, unix.NETLINK_XFRM}, "NETLINK_AUDIT": {nlAudit, unix.NETLINK_AUDIT},
		"NETLINK_NETFILTER": {nlNetfilter, unix.NETLINK_NETFILTER}, "NETLINK_CRYPTO": {nlCrypto, unix.NETLINK_CRYPTO},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s: table has %#x, x/sys has %#x", name, pair[0], pair[1])
		}
	}
	// clone(2) cannot create a time namespace: CLONE_NEWTIME is the exit
	// signal's top bit there, so the clone mask must leave it out
	if cloneNsMask&cloneNewTime != 0 {
		t.Error("the clone namespace mask includes CLONE_NEWTIME, which in clone(2) is part of the exit signal")
	}
	if cloneNsMask != 0x7e020000 {
		t.Errorf("clone namespace mask %#x, want 0x7e020000", cloneNsMask)
	}
}

func TestArchFor(t *testing.T) {
	for _, g := range []string{"amd64", "arm64"} {
		if _, ok := ArchFor(g); !ok {
			t.Errorf("no filter for %s", g)
		}
	}
	for _, g := range []string{"386", "arm", "riscv64", "ppc64le", "s390x", "mips64", ""} {
		if _, ok := ArchFor(g); ok {
			t.Errorf("a filter for %q, which has never been tested", g)
		}
	}
}
