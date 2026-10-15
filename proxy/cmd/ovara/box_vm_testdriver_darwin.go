//go:build darwin

package main

import "ovara.proxy/internal/vm"

// testVMDriver: the network-namespace stand-in exists on Linux only.
func testVMDriver(string) (vm.Driver, bool) { return nil, false }
