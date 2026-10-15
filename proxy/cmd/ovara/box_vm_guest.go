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
//   - it starts through a shim (`box-init -vm-exec`) that sets no_new_privs
//     and the box's seccomp filter before the agent's first instruction, as
//     tier 1 does (box_seccomp_linux.go);
//   - when it exits, the workspace is written as one tar for the host to
//     unpack (box_vm_tree.go): links stay links, devices and FIFOs stay out.

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"ovara.proxy/internal/boxgate"
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
	TreeOut   string   `json:"tree_out"`   // where to write the workspace tar
}

var vmUserRE = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// adminGroups are groups whose members can become root on a stock Linux
// image; the agent's user must be in none of them.
var adminGroups = map[string]bool{"root": true, "sudo": true, "admin": true, "wheel": true, "adm": true, "lxd": true, "docker": true}

func (s *vmGuestSpec) validate() error {
	if len(s.Argv) == 0 {
		return errors.New("box-init -vm: no agent command")
	}
	if !vmUserRE.MatchString(s.User) || s.User == "root" {
		return fmt.Errorf("box-init -vm: agent user %q", s.User)
	}
	if !filepath.IsAbs(s.Dir) || !filepath.IsAbs(s.TreeOut) {
		return errors.New("box-init -vm: the workspace and the tree must be absolute paths")
	}
	if s.Gate && (s.GateAddr == "" || len(s.GateToken) < 32) {
		return errors.New("box-init -vm: the command gate needs an address and the run's token")
	}
	return nil
}

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
	if err := chownTree(spec.Dir, uid, gid); err != nil {
		return 0, fmt.Errorf("box-init -vm: handing the workspace to %s: %w", spec.User, err)
	}

	self, err := os.Executable()
	if err != nil {
		return 0, err
	}
	cmd := exec.Command(self, append([]string{boxInitCmd, "-vm-exec", "--"}, spec.Argv...)...) //nolint:gosec // our own binary, then the agent command the person gave
	cmd.Env = spec.Env
	cmd.Dir = spec.Dir
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}, //nolint:gosec // validated non-negative ids from the user database
	}

	code := 0
	if spec.Gate {
		g, conn, err := dialGateTCP(spec.GateAddr, spec.GateToken, 10*time.Second)
		if err != nil {
			return 0, fmt.Errorf("box-init -vm: command gate %s: %w (refusing to start the agent without it)", spec.GateAddr, err)
		}
		defer conn.Close()
		shimSeen := false
		tr := &boxgate.Tracer{
			Decide: g.decide,
			// the shim is ours and runs before the agent; what it execs
			// next is the agent, which the host decides like any program
			Skip: func(e boxgate.Exec) bool {
				if shimSeen {
					return false
				}
				shimSeen = true
				return len(e.Argv) >= 3 && e.Argv[1] == boxInitCmd && e.Argv[2] == "-vm-exec"
			},
		}
		if code, err = tr.Run(cmd); err != nil {
			return 0, fmt.Errorf("box-init -vm: %w", err)
		}
	} else {
		if err := cmd.Run(); err != nil {
			var ee *exec.ExitError
			if !errors.As(err, &ee) {
				return 0, err
			}
			code = ee.ExitCode()
			if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
				code = 128 + int(ws.Signal())
			}
		}
	}

	// every process of the agent is gone (the tracer kills what is left
	// when the agent exits), so the tree below cannot change under us
	if err := writeTreeFile(spec.Dir, spec.TreeOut); err != nil {
		return code, fmt.Errorf("box-init -vm: packing the workspace: %w", err)
	}
	return code, nil
}

// runVMExec is the shim: running as the agent's user, it takes away new
// privileges and the cross-process memory syscalls, then becomes the agent.
func runVMExec(argv []string) error {
	if len(argv) == 0 {
		return errors.New("box-init -vm-exec: no agent command")
	}
	if os.Geteuid() == 0 {
		return errors.New("box-init -vm-exec: refusing to run the agent as root")
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("box-init -vm-exec: no_new_privs: %w", err)
	}
	if err := installBoxSeccomp(); err != nil {
		return fmt.Errorf("box-init -vm-exec: %w", err)
	}
	env := os.Environ()
	path, err := lookPathIn(argv[0], env)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ovara] %s: %v\n", termSafe(argv[0]), err)
		os.Exit(127)
	}
	err = syscall.Exec(path, argv, env) //nolint:gosec // the agent command the person gave
	fmt.Fprintf(os.Stderr, "[ovara] %s: %v\n", termSafe(argv[0]), err)
	os.Exit(126)
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

// writeTreeFile writes dir as a tar to out, readable by the guest's own user
// (the one the host copies files out as) and by no one who could change it.
func writeTreeFile(dir, out string) error {
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644) //nolint:gosec // a path the host chose, created fresh
	if err != nil {
		return err
	}
	if err := writeTree(dir, f, treeMaxBytes, treeMaxEntries); err != nil {
		f.Close()
		os.Remove(out)
		return err
	}
	return f.Close()
}

// writeTree writes dir's directories, regular files and symbolic links to
// w, links as links and every file opened without following one. Anything
// else (a FIFO, a device, a socket) is left out and said so: reading a FIFO
// the agent left would hang, and a device is not a project file.
func writeTree(dir string, w io.Writer, maxBytes int64, maxEntries int) error {
	tw := tar.NewWriter(w)
	var total int64
	n := 0
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == dir {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if n++; n > maxEntries {
			return fmt.Errorf("more than %d entries", maxEntries)
		}
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		mode := int64(info.Mode().Perm())
		switch {
		case info.IsDir():
			return tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: rel + "/", Mode: mode})
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return tw.WriteHeader(&tar.Header{Typeflag: tar.TypeSymlink, Name: rel, Linkname: target, Mode: 0o777})
		case info.Mode().IsRegular():
			if total += info.Size(); total > maxBytes {
				return fmt.Errorf("more than %d bytes of files", maxBytes)
			}
			fd, err := unix.Open(p, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				return err
			}
			f := os.NewFile(uintptr(fd), p)
			defer f.Close()
			if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: rel, Mode: mode, Size: info.Size()}); err != nil {
				return err
			}
			written, err := io.Copy(tw, io.LimitReader(f, info.Size()))
			if err != nil {
				return err
			}
			if written != info.Size() {
				return fmt.Errorf("%s changed while it was read", rel)
			}
			return nil
		default:
			fmt.Fprintf(os.Stderr, "[ovara] left in the box (not a file, directory or link): %s\n", termSafe(rel))
			return nil
		}
	})
	if err != nil {
		return err
	}
	return tw.Close()
}
