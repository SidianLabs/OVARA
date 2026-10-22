//go:build !linux

package main

import "errors"

// cmdBoxInit runs inside a box: a Linux container or a Linux VM guest.
func cmdBoxInit(args []string) error {
	return errors.New("ovara box-init runs inside a Linux box only (a container or a VM guest)")
}
