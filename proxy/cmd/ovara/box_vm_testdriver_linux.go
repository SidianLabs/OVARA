//go:build linux

package main

import (
	"fmt"
	"os"

	"ovara.proxy/internal/vm"
)

// testVMDriver is the network-namespace stand-in for a VM (internal/vm
// Netns), so the VM path of `ovara box` can run end to end on a Linux
// machine in CI. It is not an isolation boundary of its own (the "guest"
// shares this host's file system), so it is offered only when
// OVARA_BOX_VM_NETNS_TEST=1 says this is a test.
func testVMDriver(name string) (vm.Driver, bool) {
	if name != "netns-test" || os.Getenv("OVARA_BOX_VM_NETNS_TEST") != "1" {
		return nil, false
	}
	fmt.Fprintln(os.Stderr, "==> vm: netns-test is a stand-in for a VM for tests, NOT an isolation boundary")
	return &vm.Netns{}, true
}
