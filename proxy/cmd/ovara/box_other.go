//go:build !linux

package main

import "errors"

// cmdBox needs Linux (a network namespace and ptrace); elsewhere it says so.
func cmdBox(args []string) error {
	return errors.New("ovara box needs Linux (a network namespace and ptrace); on macOS/Windows run it inside a Linux VM")
}

// cmdBoxInit is PID 1 of a tier 2 box, which is a Linux container.
func cmdBoxInit(args []string) error {
	return errors.New("ovara box-init runs inside a Linux box container only")
}
