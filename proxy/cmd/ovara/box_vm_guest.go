//go:build linux

package main

// `ovara box-init -vm`: the box inside a VM (docs/box.md §10.1). `ovara box`
// on the host copies the workspace and a spec into the guest, then runs this
// as root there. The guest's network is already locked to the host's proxy
// and command gate (internal/vm); this is the part that keeps the agent from
// undoing that and puts every program it starts in front of the gate:
//
//   - the agent runs as its own unprivileged user, created here, in no
//     admin group, so it cannot unload the lockdown, read the gate's token
//     or touch the image's own (sudo-capable) user;
//   - it is traced, and every exec goes to the host's gate over TCP, opened
//     with the run's token, which only this process holds;
//   - it starts through a shim (`box-init -exec-shim`, box_shim_linux.go) that sets no_new_privs
//     and the box's seccomp filter before the agent's first instruction, as
//     tier 1 does (internal/boxseccomp);
//   - when it exits, the workspace is written as one tar for the host to
//     unpack (box_vm_tree.go): links stay links, devices and FIFOs stay out.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"ovara.proxy/internal/boxgate"
	"ovara.proxy/internal/boxseccomp"
)

// adminGroups are groups whose members can become root on a stock Linux
// image; the agent's user must be in none of them.
var adminGroups = map[string]bool{"root": true, "sudo": true, "admin": true, "wheel": true, "adm": true, "lxd": true, "docker": true}

// runVMGuest is box-init -vm SPEC. It returns the agent's exit status.
func runVMGuest(specPath string) (int, error) {
	if os.Geteuid() != 0 {
		return 0, errors.New("box-init -vm must run as root in the guest")
	}
	b, err := os.ReadFile(specPath) //nolint:gosec // the path the host passed
	if err != nil {
		return 0, fmt.Errorf("box-init -vm: reading the spec: %w", err)
	}
	// the token is in it: gone before the agent exists
	if err := os.Remove(specPath); err != nil {
		return 0, fmt.Errorf("box-init -vm: removing the spec: %w", err)
	}
	var spec vmGuestSpec
	if err := json.Unmarshal(b, &spec); err != nil {
		return 0, fmt.Errorf("box-init -vm: spec: %w", err)
	}
	if err := spec.validate(); err != nil {
		return 0, err
	}
	uid, gid, err := ensureVMAgentUser(spec.User)
	if err != nil {
		return 0, err
	}
	// the workspace arrives as a tar so that nothing in it is followed on
	// the way in; it is unpacked as strictly as on the way out
	tin, err := os.Open(spec.TreeIn) //nolint:gosec // the path the host passed
	if err != nil {
		return 0, fmt.Errorf("box-init -vm: the workspace: %w", err)
	}
	err = extractTree(tin, spec.Dir, treeMaxBytes, treeMaxEntries)
	tin.Close()
	if err != nil {
		return 0, fmt.Errorf("box-init -vm: unpacking the workspace: %w", err)
	}
	if err := os.Remove(spec.TreeIn); err != nil {
		return 0, err
	}
	if err := chownTree(spec.Dir, uid, gid); err != nil {
		return 0, fmt.Errorf("box-init -vm: handing the workspace to %s: %w", spec.User, err)
	}

	self, err := os.Executable()
	if err != nil {
		return 0, err
	}
	shim := shimArgv(self, boxseccomp.Options{AllowUserNamespaces: spec.AllowUserNS, AllowDebuggers: spec.AllowDebuggers}, spec.Argv)
	cmd := exec.Command(shim[0], shim[1:]...) //nolint:gosec // our own binary, then the agent command the person gave
	cmd.Env = spec.Env
	cmd.Dir = spec.Dir
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}, //nolint:gosec // validated non-negative ids from the user database
	}

	// a stop from the host (box-init -vm-stop) ends the agent and still
	// writes the workspace for the host
	agentDone := make(chan struct{})
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT)
	defer signal.Stop(sigs)
	go stopAgentOnSignal(sigs, agentDone, uid)

	code := 0
	if spec.Gate {
		g, conn, err := dialGateTCP(spec.GateAddr, spec.GateToken, 10*time.Second)
		if err != nil {
			return 0, fmt.Errorf("box-init -vm: command gate %s: %w (refusing to start the agent without it)", spec.GateAddr, err)
		}
		defer conn.Close()
		tr := &boxgate.Tracer{
			Decide: g.decide,
			// the shim is ours and runs before the agent; what it execs
			// next is the agent, which the host decides like any program
			Skip:    shimSkipper(),
			Changed: argvChanged,
		}
		code, err = tr.Run(cmd)
		if err != nil {
			close(agentDone)
			return 0, fmt.Errorf("box-init -vm: %w", err)
		}
	} else {
		if err := cmd.Run(); err != nil {
			var ee *exec.ExitError
			if !errors.As(err, &ee) {
				close(agentDone)
				return 0, err
			}
			code = ee.ExitCode()
			if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
				code = 128 + int(ws.Signal())
			}
		}
	}
	close(agentDone)

	// every process of the agent is gone (the tracer kills what is left
	// when the agent exits), so the tree below cannot change under us
	if err := writeTreeFile(spec.Dir, spec.TreeOut); err != nil {
		return code, fmt.Errorf("box-init -vm: packing the workspace: %w", err)
	}
	return code, nil
}

// vmStopGrace is how long the agent has after SIGTERM before SIGKILL.
var vmStopGrace = 10 * time.Second

// stopAgentOnSignal stops the agent when box-init -vm gets SIGTERM or
// SIGHUP: every process of the agent's user gets SIGTERM, then SIGKILL
// until the agent is gone (a process started meanwhile goes too). SIGINT is
// left to the terminal, which gives it to the agent itself.
func stopAgentOnSignal(sigs <-chan os.Signal, agentDone <-chan struct{}, uid int) {
	for {
		select {
		case <-agentDone:
			return
		case s := <-sigs:
			if s == syscall.SIGINT {
				continue
			}
			fmt.Fprintf(os.Stderr, "[ovara] %s: stopping the agent\n", s)
			signalUser(uid, syscall.SIGTERM)
			select {
			case <-agentDone:
				return
			case <-time.After(vmStopGrace):
			}
			for {
				signalUser(uid, syscall.SIGKILL)
				select {
				case <-agentDone:
					return
				case <-time.After(200 * time.Millisecond):
				}
			}
		}
	}
}

// signalUser sends sig to every process running as uid (real or
// effective). Never root's: uid 0 is refused.
func signalUser(uid int, sig syscall.Signal) {
	if uid <= 0 {
		return
	}
	for _, pid := range procPIDs() {
		if procHasUID(pid, uid) {
			_ = syscall.Kill(pid, sig)
		}
	}
}

func procPIDs() []int {
	ents, _ := os.ReadDir("/proc")
	var pids []int
	for _, e := range ents {
		if pid, err := strconv.Atoi(e.Name()); err == nil && pid > 0 {
			pids = append(pids, pid)
		}
	}
	return pids
}

// procHasUID reports whether pid's real or effective uid is uid.
func procHasUID(pid, uid int) bool {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(line, "Uid:"); ok {
			f := strings.Fields(rest)
			want := strconv.Itoa(uid)
			return len(f) >= 2 && (f[0] == want || f[1] == want)
		}
	}
	return false
}

// runVMStop is box-init -vm-stop SPEC, the host's way to stop a run: it
// sends SIGTERM to the root box-init -vm that was started with SPEC, which
// stops the agent and still writes the workspace. A run already over is
// not an error.
func runVMStop(specPath string) error {
	if os.Geteuid() != 0 {
		return errors.New("box-init -vm-stop must run as root in the guest")
	}
	want := []string{boxInitCmd, "-vm", specPath}
	for _, pid := range procPIDs() {
		if pid == os.Getpid() || !procHasUID(pid, 0) {
			continue
		}
		b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
		if err != nil {
			continue
		}
		argv := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
		if len(argv) == 4 && slices.Equal(argv[1:], want) {
			return syscall.Kill(pid, syscall.SIGTERM)
		}
	}
	return nil
}

// ensureVMAgentUser returns the agent user's ids, creating the user if the
// guest has none by that name, and refuses one that is root or in a group
// that can become root.
func ensureVMAgentUser(name string) (uid, gid int, err error) {
	u, err := user.Lookup(name)
	if err != nil {
		var unknown user.UnknownUserError
		if !errors.As(err, &unknown) {
			return 0, 0, err
		}
		useradd, err := systemTool("useradd")
		if err != nil {
			return 0, 0, err
		}
		out, err := exec.Command(useradd, "--system", "--create-home", "--home-dir", "/home/"+name, "--shell", "/bin/bash", name).CombinedOutput() //nolint:gosec // a validated user name
		if err != nil {
			return 0, 0, fmt.Errorf("box-init -vm: creating user %s: %v: %s", name, err, out)
		}
		if u, err = user.Lookup(name); err != nil {
			return 0, 0, err
		}
	}
	if uid, err = strconv.Atoi(u.Uid); err != nil {
		return 0, 0, err
	}
	if gid, err = strconv.Atoi(u.Gid); err != nil {
		return 0, 0, err
	}
	if uid == 0 || gid == 0 {
		return 0, 0, fmt.Errorf("box-init -vm: user %s is root", name)
	}
	gids, err := u.GroupIds()
	if err != nil {
		return 0, 0, err
	}
	for _, g := range gids {
		grp, err := user.LookupGroupId(g)
		if err != nil {
			continue
		}
		if adminGroups[grp.Name] {
			return 0, 0, fmt.Errorf("box-init -vm: user %s is in group %s, which can become root", name, grp.Name)
		}
	}
	return uid, gid, nil
}

// systemTool finds an administration tool in the system's own directories,
// never through the PATH box-init was started with: root does not run a
// program a caller's PATH points at.
func systemTool(name string) (string, error) {
	for _, d := range []string{"/usr/sbin", "/sbin", "/usr/bin", "/bin"} {
		p := filepath.Join(d, name)
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("box-init -vm: %s not found in the system directories", name)
}

// chownTree hands dir and everything under it to uid:gid, links included,
// following none.
func chownTree(dir string, uid, gid int) error {
	return filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, uid, gid)
	})
}
