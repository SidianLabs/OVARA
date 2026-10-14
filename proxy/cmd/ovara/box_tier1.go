//go:build linux

package main

// Tier 1's last step before the agent: `ovara box-init -tier1`, started
// (traced) by `ovara box` as root. It reads what to run from a pipe, never
// from its command line or environment, since that includes the agent's
// proxy token; enters the box's network namespace; unless the person asked
// for the host's file system (-tier1-fs host), builds the box's own root in a
// new mount namespace; drops to the agent's user and becomes the agent.
//
// The box's root, made fresh for each run:
//
//	/usr /bin /sbin /lib* /etc   the host's, read-only, set-uid off; the
//	                             secret parts of /etc covered (boxEtcMasked)
//	/dev                         null, zero, full, random, urandom, tty, a
//	                             private pts and shm; nothing else
//	/proc                        a new one that shows the agent's processes only
//	/tmp /var/tmp                empty, in memory
//	the workspace, the home      the run's own, read-write, at their paths
//	the CA certificate           the PUBLIC one, read-only
//	-mount SRC:DST               read-only
//
// Nothing else of the host is there: not /home, /root, /srv, /opt, /mnt,
// /var, /run, Ovara's deployment, or the original project.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// the pipe box-init -tier1 reads its spec from
const tier1SpecFD = 3

// tier1Spec is what box-init -tier1 needs to start the agent.
type tier1Spec struct {
	Netns string   `json:"netns"` // `ip netns` name; "" stays in the current one (tests)
	UID   int      `json:"uid"`
	GID   int      `json:"gid"`
	Env   []string `json:"env"`
	Argv  []string `json:"argv"`
	Dir   string   `json:"dir"` // the agent's working directory
	// Root is an empty directory, only root may enter, to build the box's
	// root in; "" runs the agent on the host's file system.
	Root  string      `json:"root,omitempty"`
	Binds []tier1Bind `json:"binds,omitempty"`
	// VisibleProcs accepts a /proc that shows every process of the host
	// when the kernel cannot hide them (-allow-visible-procs).
	VisibleProcs bool `json:"visible_procs,omitempty"`
}

// tier1Bind puts a host path into the box's root.
type tier1Bind struct {
	Src string `json:"src"`
	Dst string `json:"dst"`
	RW  bool   `json:"rw,omitempty"`
}

// what of the host's system goes into the box, read-only
var boxSystemDirs = []string{"/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/etc"}

// parts of /etc that hold secrets or say who may become root: covered by an
// empty file or directory in the box
var boxEtcMasked = []string{
	"/etc/shadow", "/etc/shadow-", "/etc/gshadow", "/etc/gshadow-",
	"/etc/sudoers", "/etc/sudoers.d", "/etc/ssh", "/etc/ssl/private",
	"/etc/security/opasswd",
}

// device nodes the box gets, bound from the host's
var boxDevices = []string{"null", "zero", "full", "random", "urandom", "tty"}

// tier1DstRefused lists where a -mount may not land in a tier 1 box: the
// box's own system, devices and run directory.
var tier1DstRefused = []string{"/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/etc", "/dev", "/proc", "/sys", "/run", "/tmp", "/var/tmp", boxRunsRoot}

// tier1Command is the traced process `ovara box` starts for a tier 1 box:
// box-init -tier1, with its spec on a pipe. Call done once the process has
// exited.
func tier1Command(self string, spec tier1Spec) (cmd *exec.Cmd, done func(), err error) {
	b, err := json.Marshal(spec)
	if err != nil {
		return nil, nil, err
	}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	go func() {
		_, _ = w.Write(b) // a box-init that died early leaves EPIPE here, once done closes r
		w.Close()
	}()
	cmd = exec.Command(self, boxInitCmd, "-tier1") //nolint:gosec // our own binary
	cmd.ExtraFiles = []*os.File{r}                 // fd 3
	cmd.Env = []string{}                           // nothing of ours; the agent's environment is in the spec
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd, func() { r.Close() }, nil
}

// runTier1Init is box-init -tier1. It never returns on success: the
// process becomes the agent.
func runTier1Init() error {
	// namespaces and credentials below are per thread until the exec;
	// box-init's init() already locked main to the main thread
	runtime.LockOSThread()
	f := os.NewFile(tier1SpecFD, "spec")
	if f == nil {
		return errors.New("box-init -tier1: no spec")
	}
	b, err := io.ReadAll(io.LimitReader(f, 4<<20))
	f.Close()
	if err != nil {
		return fmt.Errorf("box-init -tier1: reading the spec: %w", err)
	}
	var spec tier1Spec
	if err := json.Unmarshal(b, &spec); err != nil {
		return fmt.Errorf("box-init -tier1: spec: %w", err)
	}
	if spec.UID <= 0 || spec.GID <= 0 {
		return errors.New("box-init -tier1: the agent must not run as root")
	}
	if len(spec.Argv) == 0 {
		return errors.New("box-init -tier1: no agent command")
	}
	if spec.Netns != "" {
		if err := enterNetns(spec.Netns); err != nil {
			return err
		}
	}
	if spec.Root != "" {
		if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
			return fmt.Errorf("box-init -tier1: mount namespace: %w", err)
		}
		if err := buildBoxRoot(spec.Root, spec.Binds, spec.VisibleProcs); err != nil {
			return fmt.Errorf("box-init -tier1: the box's file system: %w", err)
		}
	}
	if err := os.Chdir(spec.Dir); err != nil {
		return fmt.Errorf("box-init -tier1: %w", err)
	}
	path, err := lookPathIn(spec.Argv[0], spec.Env)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ovara] %s: %v\n", termSafe(spec.Argv[0]), err)
		os.Exit(127)
	}
	// set-uid programs give the agent nothing, then the agent's user only
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("box-init -tier1: no_new_privs: %w", err)
	}
	if err := syscall.Setgroups([]int{}); err != nil {
		return fmt.Errorf("box-init -tier1: setgroups: %w", err)
	}
	if err := syscall.Setresgid(spec.GID, spec.GID, spec.GID); err != nil {
		return fmt.Errorf("box-init -tier1: setgid: %w", err)
	}
	if err := syscall.Setresuid(spec.UID, spec.UID, spec.UID); err != nil {
		return fmt.Errorf("box-init -tier1: setuid: %w", err)
	}
	err = syscall.Exec(path, spec.Argv, spec.Env) //nolint:gosec // the agent command is what the person asked `ovara box` to run
	fmt.Fprintf(os.Stderr, "[ovara] %s: %v\n", termSafe(spec.Argv[0]), err)
	os.Exit(126)
	return nil
}

func enterNetns(name string) error {
	if name == "" || strings.ContainsAny(name, "/\x00") || name == "." || name == ".." {
		return fmt.Errorf("box-init -tier1: bad network namespace name %q", name)
	}
	var fd int
	var err error
	for _, dir := range []string{"/run/netns", "/var/run/netns"} {
		if fd, err = unix.Open(filepath.Join(dir, name), unix.O_RDONLY|unix.O_CLOEXEC, 0); err == nil {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("box-init -tier1: network namespace %s: %w", name, err)
	}
	defer unix.Close(fd)
	if err := unix.Setns(fd, unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("box-init -tier1: entering network namespace %s: %w", name, err)
	}
	return nil
}

// lookPathIn resolves the agent's program with the agent's PATH, in the
// box's file system.
func lookPathIn(prog string, env []string) (string, error) {
	if strings.Contains(prog, "/") {
		return prog, nil
	}
	path := ""
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "PATH="); ok {
			path = v
		}
	}
	for _, dir := range filepath.SplitList(path) {
		if dir == "" {
			dir = "."
		}
		p := filepath.Join(dir, prog)
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", errors.New("not found in the box's PATH")
}

// buildBoxRoot makes root (an empty directory) the box's root file system
// and pivots into it. It must run in a fresh mount namespace.
func buildBoxRoot(root string, binds []tier1Bind, visibleProcs bool) error {
	// nothing done here may reach the host's mount table
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("making mounts private: %w", err)
	}
	if err := unix.Mount("tmpfs", root, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0755,size=4m"); err != nil {
		return fmt.Errorf("root: %w", err)
	}
	in := func(p string) string { return filepath.Join(root, p) }

	// the host's system, read-only
	for _, d := range boxSystemDirs {
		st, err := os.Lstat(d)
		if err != nil {
			continue
		}
		if st.Mode()&os.ModeSymlink != 0 { // merged /usr: /bin -> usr/bin
			target, err := os.Readlink(d)
			if err != nil {
				return err
			}
			if err := os.Symlink(target, in(d)); err != nil {
				return err
			}
			continue
		}
		if !st.IsDir() {
			continue
		}
		if err := os.Mkdir(in(d), 0o755); err != nil {
			return err
		}
		if err := bindReadOnly(d, in(d)); err != nil {
			return err
		}
	}
	for _, p := range boxEtcMasked {
		if err := mask(in(p)); err != nil {
			return fmt.Errorf("covering %s: %w", p, err)
		}
	}

	// /dev: a few devices, a private pts, shm
	dev := in("/dev")
	if err := os.Mkdir(dev, 0o755); err != nil {
		return err
	}
	if err := unix.Mount("tmpfs", dev, "tmpfs", unix.MS_NOSUID|unix.MS_NOEXEC, "mode=0755,size=64k"); err != nil {
		return fmt.Errorf("/dev: %w", err)
	}
	for _, d := range boxDevices {
		if err := os.WriteFile(filepath.Join(dev, d), nil, 0o666); err != nil { //nolint:gosec // a bind-mount target: what is mounted over it sets the mode
			return err
		}
		if err := unix.Mount("/dev/"+d, filepath.Join(dev, d), "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("/dev/%s: %w", d, err)
		}
	}
	if err := os.Mkdir(filepath.Join(dev, "pts"), 0o755); err != nil {
		return err
	}
	if err := unix.Mount("devpts", filepath.Join(dev, "pts"), "devpts", unix.MS_NOSUID|unix.MS_NOEXEC, "newinstance,ptmxmode=0666,mode=0620"); err != nil {
		return fmt.Errorf("/dev/pts: %w", err)
	}
	if err := os.Mkdir(filepath.Join(dev, "shm"), 0o1777); err != nil {
		return err
	}
	if err := unix.Mount("tmpfs", filepath.Join(dev, "shm"), "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=1777,size=512m"); err != nil {
		return fmt.Errorf("/dev/shm: %w", err)
	}
	for name, target := range map[string]string{"ptmx": "pts/ptmx", "fd": "/proc/self/fd", "stdin": "/proc/self/fd/0", "stdout": "/proc/self/fd/1", "stderr": "/proc/self/fd/2"} {
		if err := os.Symlink(target, filepath.Join(dev, name)); err != nil {
			return err
		}
	}

	// /proc: a new one; the agent sees its own processes only.
	if err := os.Mkdir(in("/proc"), 0o555); err != nil {
		return err
	}
	pflags := uintptr(unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC)
	if err := mountBoxProc(func(opts string) error {
		return unix.Mount("proc", in("/proc"), "proc", pflags, opts)
	}, visibleProcs); err != nil {
		return err
	}

	// scratch space
	for _, d := range []string{"/tmp", "/var/tmp"} {
		if err := os.MkdirAll(in(d), 0o755); err != nil {
			return err
		}
		if err := unix.Mount("tmpfs", in(d), "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=1777"); err != nil {
			return fmt.Errorf("%s: %w", d, err)
		}
	}
	if err := os.Mkdir(in("/run"), 0o755); err != nil {
		return err
	}

	// the run's own paths and -mount, parents first
	sorted := append([]tier1Bind(nil), binds...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Dst < sorted[j].Dst })
	for _, bd := range sorted {
		st, err := os.Stat(bd.Src)
		if err != nil {
			return err
		}
		dst := in(bd.Dst)
		if err := mountpointNoFollow(root, bd.Dst, st.IsDir()); err != nil {
			return fmt.Errorf("%s: %w", bd.Dst, err)
		}
		if bd.RW {
			if err := unix.Mount(bd.Src, dst, "", unix.MS_BIND, ""); err != nil {
				return fmt.Errorf("%s: %w", bd.Dst, err)
			}
			if err := unix.Mount("", dst, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
				return fmt.Errorf("%s: %w", bd.Dst, err)
			}
			continue
		}
		if err := bindReadOnly(bd.Src, dst); err != nil {
			return fmt.Errorf("%s: %w", bd.Dst, err)
		}
	}

	// in, and the host's tree gone
	old := in("/.old")
	if err := os.Mkdir(old, 0o700); err != nil {
		return err
	}
	if err := unix.PivotRoot(root, old); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}
	if err := os.Chdir("/"); err != nil {
		return err
	}
	if err := unix.Unmount("/.old", unix.MNT_DETACH); err != nil {
		return fmt.Errorf("detaching the host's tree: %w", err)
	}
	if err := os.Remove("/.old"); err != nil {
		return err
	}
	if err := unix.Mount("", "/", "", unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
		return fmt.Errorf("root read-only: %w", err)
	}
	return nil
}

// errVisibleProcs is the refusal when /proc cannot hide other users'
// processes.
var errVisibleProcs = errors.New("this kernel cannot give the box a /proc that hides other users' processes " +
	"(hidepid=invisible on a private /proc needs Linux 5.8 or later); the agent would see every process on the host " +
	"and their command lines. Use -tier 2, or pass -allow-visible-procs to accept that")

// mountBoxProc mounts the box's /proc with hidepid=invisible. A kernel
// before 5.8 has no per-mount hidepid (setting it there would change the
// host's /proc too): then the box is refused, unless visibleProcs accepts
// a plain /proc.
func mountBoxProc(mount func(opts string) error, visibleProcs bool) error {
	err := mount("hidepid=invisible")
	if err == nil {
		return nil
	}
	if !visibleProcs {
		return fmt.Errorf("/proc: %w (%v)", errVisibleProcs, err)
	}
	if err := mount(""); err != nil {
		return fmt.Errorf("/proc: %w", err)
	}
	fmt.Fprintln(os.Stderr, "[ovara] -allow-visible-procs: the box's /proc shows every process on the host")
	return nil
}

// bindReadOnly binds src at dst with everything under it, read-only and
// set-uid off, submounts included.
func bindReadOnly(src, dst string) error {
	if err := unix.Mount(src, dst, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return err
	}
	mps, err := mountsUnder(dst)
	if err != nil {
		return err
	}
	for _, mp := range mps {
		if err := unix.Mount("", mp, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
			return fmt.Errorf("read-only %s: %w", mp, err)
		}
	}
	return nil
}

// mountsUnder lists dst and every mount point below it in this thread's
// mount namespace.
func mountsUnder(dst string) ([]string, error) {
	b, err := os.ReadFile("/proc/thread-self/mountinfo")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		mp := unescapeMountinfo(f[4])
		if mp == dst || strings.HasPrefix(mp, dst+"/") {
			out = append(out, mp)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s is not a mount point", dst)
	}
	return out, nil
}

// unescapeMountinfo undoes mountinfo's octal escapes (\040 for a space).
func unescapeMountinfo(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// mask covers p, if it is there, with an empty read-only file or directory.
func mask(p string) error {
	st, err := os.Lstat(p)
	if err != nil || st.Mode()&os.ModeSymlink != 0 {
		return nil //nolint:nilerr // absent: nothing to cover; a symlink points into the box, covered or absent there
	}
	if st.IsDir() {
		return unix.Mount("tmpfs", p, "tmpfs", unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "mode=0755,size=4k")
	}
	if err := unix.Mount("/dev/null", p, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	return unix.Mount("", p, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "")
}

// mountpointNoFollow creates dst under root (a directory, or an empty file
// for a file bind) without following a symlink anywhere on the way: a link
// in the box's root could otherwise lead the mkdir out of it.
func mountpointNoFollow(root, dst string, dir bool) error {
	clean := filepath.Clean("/" + dst)
	if clean == "/" {
		return errors.New("refusing to cover the box's root")
	}
	parts := strings.Split(strings.TrimPrefix(clean, "/"), "/")
	cur := root
	for i, p := range parts {
		cur = filepath.Join(cur, p)
		last := i == len(parts)-1
		st, err := os.Lstat(cur)
		switch {
		case err == nil && st.Mode()&os.ModeSymlink != 0:
			return errors.New("the path goes through a symbolic link in the box")
		case err == nil && last && st.IsDir() != dir:
			return errors.New("a file and a directory at the same place")
		case err == nil && !last && !st.IsDir():
			return errors.New("not a directory on the way")
		case err == nil:
			continue
		case !errors.Is(err, os.ErrNotExist):
			return err
		}
		if !last || dir {
			if err := os.Mkdir(cur, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.WriteFile(cur, nil, 0o644); err != nil { //nolint:gosec // a bind-mount target: what is mounted over it sets the mode
			return err
		}
	}
	return nil
}
