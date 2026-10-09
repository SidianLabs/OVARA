//go:build windows

package workspace

// ownerOf is unknown on Windows: commit-back runs as the current user.
func ownerOf(path string) (uid, gid int) { return -1, -1 }

// gitAs runs git as ourselves on Windows.
func gitAs(owner [2]int, dir string, args ...string) (string, error) { return gitOut(dir, args...) }
