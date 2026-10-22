//go:build darwin

package main

import "errors"

// On macOS the box runs in a Linux VM (box_vm_host.go); tiers 1 and 2 need
// a Linux kernel on the host itself.

var errTierNeedsLinux = errors.New("tiers 1 and 2 need a Linux host; on macOS the box runs in a VM (-vm lima)")

func runTier1(*boxAgent) (int, error)             { return 0, errTierNeedsLinux }
func runTier2(*boxAgent) (int, error)             { return 0, errTierNeedsLinux }
func ensureUser(string) (uid, gid int, err error) { return 0, 0, errTierNeedsLinux }
