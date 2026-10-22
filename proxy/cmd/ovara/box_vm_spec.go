package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
)

// vmGuestSpec is what the host hands box-init -vm: a file in the guest that
// box-init reads and removes before the agent exists.
type vmGuestSpec struct {
	Argv      []string `json:"argv"`
	Env       []string `json:"env"`
	Dir       string   `json:"dir"`  // the workspace in the guest
	User      string   `json:"user"` // created if missing; never root or an admin
	Gate      bool     `json:"gate"`
	GateAddr  string   `json:"gate_addr"`  // host:port of the host's command gate
	GateToken string   `json:"gate_token"` // opens it
	TreeIn    string   `json:"tree_in"`    // the workspace as a tar, unpacked into Dir
	TreeOut   string   `json:"tree_out"`   // where to write the workspace tar
	// the seccomp opt-outs (-allow-user-namespaces, -allow-debuggers)
	AllowUserNS    bool `json:"allow_userns,omitempty"`
	AllowDebuggers bool `json:"allow_debuggers,omitempty"`
}

var vmUserRE = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

func (s *vmGuestSpec) validate() error {
	if len(s.Argv) == 0 {
		return errors.New("box-init -vm: no agent command")
	}
	if !vmUserRE.MatchString(s.User) || s.User == "root" {
		return fmt.Errorf("box-init -vm: agent user %q", s.User)
	}
	if !filepath.IsAbs(s.Dir) || !filepath.IsAbs(s.TreeIn) || !filepath.IsAbs(s.TreeOut) {
		return errors.New("box-init -vm: the workspace and its trees must be absolute paths")
	}
	if s.Gate && (s.GateAddr == "" || len(s.GateToken) < 32) {
		return errors.New("box-init -vm: the command gate needs an address and the run's token")
	}
	return nil
}
