// Package fsperm answers "is this secret-bearing file readable by anyone
// other than its owner?" in a platform-aware way.
//
// On Unix the answer comes from the mode bits. Windows has no group/other
// mode bits (os.FileMode reports 0666 for ordinary files), so the same
// check could never pass there and made every secret file "unsafe",
// stopping the gateway from starting. On Windows, access to the file is
// governed by the ACL inherited from the user's profile directory, which
// is private to the user by default; keep deployment directories under it.
package fsperm

import "os"

// OpenToOthers reports whether st is accessible to group or other users.
func OpenToOthers(st os.FileInfo) bool { return openToOthers(st) }
