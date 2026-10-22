//go:build linux

package vm

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestLockdown_GuestReachesOnlyTheProxyAndGate runs the real provisioning
// script in a network namespace standing in for the VM guest (the guest is
// just a Linux kernel; only the hypervisor is missing), then checks from
// inside it: the host's proxy and gate ports answer, while another port on
// the host, DNS and QUIC do not. Needs root, ip and nft; CI runs it in the
// root job.
func TestLockdown_GuestReachesOnlyTheProxyAndGate(t *testing.T) {
	// CI sets OVARA_REQUIRE_LOCKDOWN_TEST=1 in the root job, so a missing
	// prerequisite there is a failure rather than a skip that reads as a pass.
	skip := t.Skipf
	if os.Getenv("OVARA_REQUIRE_LOCKDOWN_TEST") == "1" {
		skip = t.Fatalf
	}
	if os.Geteuid() != 0 {
		skip("needs root (network namespaces)")
	}
	for _, tool := range []string{"ip", "nft", "bash", "timeout", "getent"} {
		if _, err := exec.LookPath(tool); err != nil {
			skip("needs %s", tool)
		}
	}
	n := os.Getpid() % 10000
	ns := fmt.Sprintf("ovara-vmtest-%d", n)
	hostIf, guestIf := fmt.Sprintf("ovt%dh", n), fmt.Sprintf("ovt%dg", n)
	const hostIP, guestIP = "10.231.0.1", "10.231.0.2"

	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil { //nolint:gosec // fixed test commands
			t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	run("ip", "netns", "add", ns)
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "del", ns).Run()    //nolint:gosec // test cleanup
		_ = exec.Command("ip", "link", "del", hostIf).Run() //nolint:gosec // test cleanup
		_ = os.RemoveAll(filepath.Join("/etc/netns", ns))
	})
	run("ip", "link", "add", hostIf, "type", "veth", "peer", "name", guestIf)
	run("ip", "link", "set", guestIf, "netns", ns)
	run("ip", "addr", "add", hostIP+"/30", "dev", hostIf)
	run("ip", "link", "set", hostIf, "up")
	run("ip", "netns", "exec", ns, "ip", "addr", "add", guestIP+"/30", "dev", guestIf)
	run("ip", "netns", "exec", ns, "ip", "link", "set", guestIf, "up")
	run("ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up")
	// `ip netns exec` mounts /etc/netns/<ns>/hosts over /etc/hosts, the
	// way Lima writes host.lima.internal into the guest's hosts file.
	if err := os.MkdirAll(filepath.Join("/etc/netns", ns), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("/etc/netns", ns, "hosts"), []byte("127.0.0.1 localhost\n"+hostIP+" "+limaHost+"\n"), 0o644); err != nil { //nolint:gosec // a hosts file
		t.Fatal(err)
	}

	// listeners on the host side: the two allowed ports, one that is not,
	// and TCP 53; each answers "ok" so a connection that gets through shows it
	listen := func() int {
		ln, err := net.Listen("tcp", hostIP+":0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				_, _ = c.Write([]byte("ok\n"))
				c.Close()
			}
		}()
		return ln.Addr().(*net.TCPAddr).Port
	}
	proxyPort := listen()
	gatePort := listen()
	otherPort := listen()
	dns, err := net.Listen("tcp", hostIP+":53")
	if err == nil {
		t.Cleanup(func() { dns.Close() })
		go func() {
			for {
				c, err := dns.Accept()
				if err != nil {
					return
				}
				_, _ = c.Write([]byte("ok\n"))
				c.Close()
			}
		}()
	}
	quic, err := net.ListenPacket("udp", hostIP+":443")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { quic.Close() })

	reach := func(port int) bool {
		out, err := exec.Command("ip", "netns", "exec", ns, "timeout", "3", "bash", "-c", //nolint:gosec // fixed test command
			"exec 3<>/dev/tcp/"+hostIP+"/"+strconv.Itoa(port)+" && head -c 2 <&3").Output()
		return err == nil && string(out) == "ok"
	}

	// before the lockdown everything answers, so the checks below are
	// measuring the rules and not a broken link
	if !reach(otherPort) {
		t.Fatal("the test link does not work even without the lockdown")
	}

	script := provisionScript(limaHost, proxyPort, gatePort)
	for i := 0; i < 2; i++ { // twice: Lima runs provisioning at every boot
		cmd := exec.Command("ip", "netns", "exec", ns, "bash", "-s") //nolint:gosec // fixed test command
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("provisioning run %d: %v\n%s", i+1, err, out)
		}
	}

	if !reach(proxyPort) {
		t.Error("the guest cannot reach the host's proxy port")
	}
	if !reach(gatePort) {
		t.Error("the guest cannot reach the host's gate port")
	}
	if reach(otherPort) {
		t.Error("the guest reached another port on the host")
	}
	if dns != nil && reach(53) {
		t.Error("the guest reached TCP 53 on the host")
	}
	// QUIC: a UDP datagram to 443 must not arrive
	_ = exec.Command("ip", "netns", "exec", ns, "bash", "-c", "echo x > /dev/udp/"+hostIP+"/443").Run() //nolint:gosec // fixed test command
	_ = quic.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := quic.ReadFrom(make([]byte, 16)); err == nil {
		t.Error("a UDP datagram to 443 left the guest")
	}
	// the table is there under the name Verify looks for
	out, err := exec.Command("ip", "netns", "exec", ns, "nft", "list", "table", "inet", lockdownTable).CombinedOutput() //nolint:gosec // fixed test command
	if err != nil || !strings.Contains(string(out), "policy drop") {
		t.Errorf("lockdown table not as Verify expects: %v\n%s", err, out)
	}
}
