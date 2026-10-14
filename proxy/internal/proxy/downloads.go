package proxy

import (
	"fmt"
	"mime"
	"net/http"
	"path"
	"strings"
)

// Executable downloads. A browser agent, or a coding agent fetching an
// installer, gets a file the policy saw only as a read of a URL. When
// the response turns out to deliver an executable or an installer, a
// person decides before it reaches the agent: the download is a question
// of its own (download.file on download:<host><path>) with the file's
// name, type and size in front of them. Archives and documents are not
// asked about: what runs is caught by the box's command gate.

const actionDownload = "download.file"

// installerExts are the file extensions that are executables or installers.
var installerExts = map[string]bool{
	"exe": true, "msi": true, "msix": true, "dmg": true, "pkg": true, "deb": true, "rpm": true,
	"apk": true, "ipa": true, "appimage": true, "snap": true, "flatpak": true, "run": true,
	"sh": true, "bash": true, "zsh": true, "ksh": true, "ps1": true, "bat": true, "cmd": true,
	"com": true, "scr": true, "vbs": true, "jar": true,
}

// executableTypes are the media types that are executables or installers.
var executableTypes = map[string]bool{
	"application/x-msdownload": true, "application/x-msdos-program": true,
	"application/vnd.microsoft.portable-executable": true, "application/x-executable": true,
	"application/x-elf": true, "application/x-mach-binary": true, "application/x-sh": true,
	"application/x-shellscript": true, "application/x-apple-diskimage": true,
	"application/vnd.debian.binary-package": true, "application/x-debian-package": true,
	"application/x-rpm": true, "application/x-redhat-package-manager": true,
	"application/java-archive": true, "application/vnd.android.package-archive": true,
	"application/x-ms-installer": true, "application/x-msi": true, "application/vnd.appimage": true,
}

// executableDownload reports a response that delivers an executable or an
// installer: by the file name Content-Disposition gives, else the URL's
// last path segment, or by the media type. It returns the name and type
// as a person should read them.
func executableDownload(r *http.Request, resp *http.Response) (name, kind string, ok bool) {
	if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		if _, params, err := mime.ParseMediaType(cd); err == nil {
			name = params["filename"]
		}
	}
	if name == "" {
		if base := path.Base(r.URL.Path); base != "/" && base != "." {
			name = base
		}
	}
	name = strings.TrimSpace(name)
	kind = undeclaredType
	if mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err == nil {
		kind = mt
	}
	ext := strings.ToLower(strings.TrimPrefix(path.Ext(name), "."))
	if !installerExts[ext] && !executableTypes[kind] {
		return "", "", false
	}
	if name == "" {
		name = "(unnamed file)"
	}
	return truncate(name, 80), truncate(kind, 60), true
}

// downloadPreview is what the person sees about an executable download.
func downloadPreview(name, kind string, length int64) map[string]string {
	size := "size unknown"
	if length >= 0 {
		size = fmt.Sprintf("%d bytes", length)
	}
	return map[string]string{
		"download": fmt.Sprintf("%s (%s, %s)", name, kind, size),
		"why":      "an executable or installer is coming back: a person decides before it reaches the agent",
	}
}
