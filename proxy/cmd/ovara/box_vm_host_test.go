//go:build linux || darwin

package main

import (
	"runtime"
	"testing"
)

func TestVMSpecFor_Sizing(t *testing.T) {
	a := &boxAgent{runID: "20261015-082603"}
	s, err := vmSpecFor(a, 9443, 40000)
	if err != nil {
		t.Fatal(err)
	}
	if s.Name != "ovara-box-20261015-082603" || s.MemoryGiB != 8 || s.CPUs < 1 || s.CPUs > 4 {
		t.Fatalf("defaults: %+v", s)
	}
	for mem, want := range map[string]int{"16g": 16, "8GiB": 8, "4": 4} {
		a.memory = mem
		s, err := vmSpecFor(a, 9443, 40000)
		if err != nil || s.MemoryGiB != want {
			t.Errorf("-memory %s: %d %v, want %d", mem, s.MemoryGiB, err, want)
		}
	}
	a.memory, a.cpus = "", "2"
	if s, err := vmSpecFor(a, 9443, 40000); err != nil || s.CPUs != 2 {
		t.Errorf("-cpus 2: %+v %v", s, err)
	}
	for _, bad := range []*boxAgent{
		{runID: "x", cpus: "two"},
		{runID: "x", memory: "lots"},
		{runID: "x", cpus: "0"},
		{runID: "x", memory: "100000g"},
	} {
		if _, err := vmSpecFor(bad, 9443, 40000); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if _, err := vmSpecFor(&boxAgent{runID: "x"}, 9443, 9443); err == nil {
		t.Error("accepted the same port for the proxy and the gate")
	}
}

func TestGuestBinary(t *testing.T) {
	if got, err := guestBinary("/opt/ovara-linux-arm64", "/usr/local/bin/ovara"); err != nil || got != "/opt/ovara-linux-arm64" {
		t.Errorf("-vm-binary: %q %v", got, err)
	}
	got, err := guestBinary("", "/usr/local/bin/ovara")
	if runtime.GOOS == "linux" {
		if err != nil || got != "/usr/local/bin/ovara" {
			t.Errorf("linux host: %q %v, want this binary", got, err)
		}
	} else if err == nil {
		t.Errorf("macOS host without ovara-linux next to it: %q, want an error saying how to get it", got)
	}
}
