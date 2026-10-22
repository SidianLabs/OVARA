//go:build linux

package main

import (
	"slices"
	"testing"

	"ovara.proxy/internal/boxgate"
	"ovara.proxy/internal/boxseccomp"
)

func TestShimArgv(t *testing.T) {
	agent := []string{"-allow-userns", "--", "bash", "-c", "echo hi"} // an agent whose own arguments look like ours
	cases := []struct {
		o    boxseccomp.Options
		want []string
	}{
		{boxseccomp.Options{}, []string{"/o/ovara", "box-init", "-exec-shim", "--"}},
		{boxseccomp.Options{AllowUserNamespaces: true}, []string{"/o/ovara", "box-init", "-exec-shim", "-allow-userns", "--"}},
		{boxseccomp.Options{AllowDebuggers: true}, []string{"/o/ovara", "box-init", "-exec-shim", "-allow-debuggers", "--"}},
		{boxseccomp.Options{AllowUserNamespaces: true, AllowDebuggers: true}, []string{"/o/ovara", "box-init", "-exec-shim", "-allow-userns", "-allow-debuggers", "--"}},
	}
	for _, c := range cases {
		got := shimArgv("/o/ovara", c.o, agent)
		if want := append(slices.Clone(c.want), agent...); !slices.Equal(got, want) {
			t.Errorf("shimArgv(%+v) = %q, want %q", c.o, got, want)
		}
	}
}

// the gate lets exactly one exec through unasked, the first, and only if it is
// the shim: a program that later runs the shim itself is checked like any other
func TestShimSkipperLetsOnlyTheFirstShimExecThrough(t *testing.T) {
	shim := boxgate.Exec{Argv: []string{"/o/ovara", "box-init", "-exec-shim", "--", "sh"}}
	other := boxgate.Exec{Argv: []string{"/bin/sh", "-c", "true"}}

	skip := shimSkipper()
	if !skip(shim) {
		t.Error("the shim's own exec was not let through")
	}
	if skip(shim) {
		t.Error("a second shim exec was let through: an agent could run the shim to start an unchecked program")
	}
	if skip(other) {
		t.Error("an ordinary exec was let through")
	}

	// a first exec that is NOT the shim consumes the latch and is checked
	skip = shimSkipper()
	if skip(other) {
		t.Error("an ordinary first exec was let through")
	}
	if skip(shim) {
		t.Error("the shim was let through after another exec had been seen first")
	}
	if shimSkipper()(boxgate.Exec{Argv: []string{"/o/ovara", "box-init"}}) {
		t.Error("a box-init without -exec-shim was let through")
	}
	if shimSkipper()(boxgate.Exec{}) {
		t.Error("an empty exec was let through")
	}
}
