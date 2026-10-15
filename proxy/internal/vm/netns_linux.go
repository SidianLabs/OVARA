//go:build linux

package vm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
)

// Netns is a stand-in for a VM, for testing the VM path of `ovara box` on a
// Linux machine without a hypervisor: the "guest" is a network namespace
// with the same lockdown a Lima guest gets, and its file system is the
// host's. It is NOT an isolation boundary of its own and `ovara box` offers
// it only to tests (OVARA_BOX_VM_NETNS_TEST=1). Needs root, ip and nft.
type Netns struct {
	root    string // the per-VM directory standing in for the guest's GuestDir
	hostIP  string
	hostIf  string
	nsName  string
	created atomic.Bool
}

var netnsSeq atomic.Int32

const netnsHostName = "host.ovara.test"

func (n *Netns) Name() string       { return "netns-test" }
func (n *Netns) HostName() string   { return netnsHostName }
func (n *Netns) HostListen() string { return n.hostIP }
func (n *Netns) GuestDir() string   { return filepath.Join(n.root, "run") }

func (n *Netns) run(args ...string) error {
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput() //nolint:gosec // fixed commands with validated names
	if err != nil {
		return fmt.Errorf("%s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Prepare picks the namespace's addresses before Create, so the host can
// listen on HostListen first and put those ports in the spec.
func (n *Netns) Prepare(name string) error {
	if !ValidName(name) {
		return fmt.Errorf("vm name %q is not one Ovara made", name)
	}
	if os.Geteuid() != 0 {
		return errors.New("the netns test VM needs root")
	}
	k := (os.Getpid()+int(netnsSeq.Add(1)))%200 + 20
	n.nsName = name
	n.hostIP = fmt.Sprintf("10.233.%d.1", k)
	n.hostIf = fmt.Sprintf("ovnt%dh", k)
	root, err := os.MkdirTemp("/var/tmp", name+"-")
	if err != nil {
		return err
	}
	if err := os.Chmod(root, 0o755); err != nil {
		return err
	}
	n.root = root
	// the address must exist on the host before anything listens on it
	if err := n.run("ip", "link", "add", n.hostIf, "type", "veth", "peer", "name", n.hostIf[:len(n.hostIf)-1]+"g"); err != nil {
		return err
	}
	if err := n.run("ip", "addr", "add", n.hostIP+"/30", "dev", n.hostIf); err != nil {
		return err
	}
	return n.run("ip", "link", "set", n.hostIf, "up")
}

func (n *Netns) Create(_ context.Context, spec Spec) error {
	if err := spec.Validate(); err != nil {
		return err
	}
	if spec.Name != n.nsName {
		return errors.New("netns test VM: Prepare it with the same name first")
	}
	guestIf := n.hostIf[:len(n.hostIf)-1] + "g"
	guestIP := strings.TrimSuffix(n.hostIP, ".1") + ".2"
	steps := [][]string{
		{"ip", "netns", "add", n.nsName},
		{"ip", "link", "set", guestIf, "netns", n.nsName},
		{"ip", "netns", "exec", n.nsName, "ip", "addr", "add", guestIP + "/30", "dev", guestIf},
		{"ip", "netns", "exec", n.nsName, "ip", "link", "set", guestIf, "up"},
		{"ip", "netns", "exec", n.nsName, "ip", "link", "set", "lo", "up"},
	}
	for _, s := range steps {
		if err := n.run(s...); err != nil {
			return err
		}
	}
	n.created.Store(true)
	etc := filepath.Join("/etc/netns", n.nsName)
	if err := os.MkdirAll(etc, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(etc, "hosts"), []byte("127.0.0.1 localhost\n"+n.hostIP+" "+netnsHostName+"\n"), 0o644); err != nil { //nolint:gosec // a hosts file
		return err
	}
	cmd := exec.Command("ip", "netns", "exec", n.nsName, "bash", "-s") //nolint:gosec // fixed command
	cmd.Stdin = strings.NewReader(provisionScript(netnsHostName, spec.ProxyPort, spec.GatePort))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("netns test VM: provisioning: %w: %s", err, out)
	}
	return nil
}

func (n *Netns) Verify(_ context.Context, name string) error {
	if name != n.nsName {
		return fmt.Errorf("vm name %q is not this test VM", name)
	}
	out, err := exec.Command("ip", "netns", "exec", n.nsName, "nft", "list", "table", "inet", lockdownTable).CombinedOutput() //nolint:gosec // fixed command
	if err != nil || !strings.Contains(string(out), "policy drop") {
		return fmt.Errorf("vm %s: the network lockdown is not loaded: %v", name, err)
	}
	pout, err := exec.Command("ip", "netns", "exec", n.nsName, "bash", "-c", probeScript).Output() //nolint:gosec // fixed command
	if err != nil || strings.TrimSpace(string(pout)) != "BLOCKED" {
		return fmt.Errorf("vm %s: a direct connection out was not blocked", name)
	}
	return nil
}

// CopyIn and CopyOut copy within the host's file system, the "guest's".
func (n *Netns) CopyIn(_ context.Context, name, hostSrc, guestDst string) error {
	if name != n.nsName {
		return fmt.Errorf("vm name %q is not this test VM", name)
	}
	return copyPath(hostSrc, guestDst)
}

func (n *Netns) CopyOut(_ context.Context, name, guestSrc, hostDst string) error {
	if name != n.nsName {
		return fmt.Errorf("vm name %q is not this test VM", name)
	}
	return copyPath(guestSrc, hostDst)
}

func (n *Netns) Run(ctx context.Context, name string, argv []string, stdio Stdio) (int, error) {
	if name != n.nsName {
		return 0, fmt.Errorf("vm name %q is not this test VM", name)
	}
	if len(argv) == 0 {
		return 0, errors.New("vm run: no command")
	}
	cmd := exec.CommandContext(ctx, "ip", append([]string{"netns", "exec", n.nsName}, argv...)...) //nolint:gosec // the box's own guest command
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdio.Stdin, stdio.Stdout, stdio.Stderr
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	return 0, err
}

func (n *Netns) Delete(_ context.Context, name string) error {
	if name != n.nsName {
		return fmt.Errorf("vm name %q is not this test VM", name)
	}
	if n.created.Load() {
		_ = n.run("ip", "netns", "del", n.nsName)
	}
	_ = exec.Command("ip", "link", "del", n.hostIf).Run() //nolint:gosec // fixed command
	_ = os.RemoveAll(filepath.Join("/etc/netns", n.nsName))
	if n.root != "" {
		return os.RemoveAll(n.root)
	}
	return nil
}

// copyPath copies a regular file, or a directory of regular files and
// directories, from src to dst (which must not exist).
func copyPath(src, dst string) error {
	st, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if st.IsDir() {
		if err := os.Mkdir(dst, st.Mode().Perm()); err != nil {
			return err
		}
		entries, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if err := copyPath(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())); err != nil {
				return err
			}
		}
		return nil
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("copy %s: not a file or directory", src)
	}
	in, err := os.Open(src) //nolint:gosec // a path the launcher chose
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, st.Mode().Perm()) //nolint:gosec // a path the launcher chose
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

var _ Driver = (*Netns)(nil)
