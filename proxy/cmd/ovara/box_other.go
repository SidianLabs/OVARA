//go:build !linux

package main

import "errors"

// cmdBox needs Linux (a network namespace and ptrace); elsewhere it only
// writes a run down (-print-manifest) for a Linux machine to run.
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

// cmdBoxInit is PID 1 of a tier 2 box, which is a Linux container.
func cmdBoxInit(args []string) error {
	return errors.New("ovara box-init runs inside a Linux box container only")
}
