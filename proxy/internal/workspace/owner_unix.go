//go:build !windows

package workspace

import (
	"bytes"
	"errors"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// chownTree hands root and everything under it to uid:gid when we are root
// and that is someone else; otherwise it does nothing.
func chownTree(root string, uid, gid int) error {
	if os.Geteuid() != 0 || uid <= 0 || gid < 0 {
		return nil
	}
	return filepath.Walk(root, func(p string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, uid, gid)
	})
}

// ownerOf returns the uid/gid owning path, or -1 when unknown.
func ownerOf(path string) (uid, gid int) {
	info, err := os.Stat(path)
	if err != nil {
		return -1, -1
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid), int(st.Gid)
	}
	return -1, -1
}

// gitAs runs git as the given user when we are root and that user is not;
// otherwise as ourselves.
func gitAs(owner [2]int, dir string, args ...string) (string, error) {
	uid, gid := owner[0], owner[1]
	if os.Geteuid() != 0 || uid <= 0 || gid < 0 || uid > math.MaxUint32 || gid > math.MaxUint32 {
		return gitOut(dir, args...)
	}
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), gitEnv...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), NoSetGroups: true}}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", errors.New("git " + strings.Join(args, " ") + ": " + msg)
	}
	return out.String(), nil
}
