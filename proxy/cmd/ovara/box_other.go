//go:build !linux && !darwin

package main

import "errors"

// cmdBox runs on Linux (tiers 1 and 2) and macOS (a VM); elsewhere (Windows,
// until its WSL2 driver) it only writes a run down (-print-manifest) for a
// machine that can run it.
func cmdBox(args []string) error {
	o, x, err := parseBoxArgs(args)
	if err != nil {
		return err
	}
	if x.printManifest {
		return printManifest(o)
	}
	return errors.New("ovara box needs Linux (a network namespace and ptrace); on macOS/Windows run it inside a Linux VM, or write the run down with -print-manifest and run it there with -manifest")
}
