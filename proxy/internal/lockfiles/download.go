package lockfiles

import (
	"net/url"
	"strings"
)

// Download recognises the fetch of one package artifact on the pinned
// registries and names it like Scan does. Metadata reads (an npm packument,
// a PyPI index page, a Go .info/.mod) are not artifacts and are not named:
// only the download of code is gated.
//
//	registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz          npm:left-pad@1.3.0
//	registry.npmjs.org/@types/node/-/node-20.1.0.tgz          npm:@types/node@20.1.0
//	files.pythonhosted.org/packages/../six-1.16.0-py2.py3-none-any.whl   pypi:six@1.16.0
//	files.pythonhosted.org/packages/../Django-4.2.tar.gz      pypi:django@4.2
//	proxy.golang.org/github.com/!foo/bar/@v/v1.2.3.zip        go:github.com/Foo/bar@v1.2.3
//	static.crates.io/crates/serde/serde-1.0.200.crate         crate:serde@1.0.200
func Download(host, path string) (string, bool) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if p, err := url.PathUnescape(path); err == nil {
		path = p
	}
	switch host {
	case "registry.npmjs.org", "registry.yarnpkg.com":
		return npmTarball(path)
	case "files.pythonhosted.org":
		return pypiFile(path)
	case "proxy.golang.org":
		return goZip(path)
	case "static.crates.io":
		return crateFile(path)
	}
	return "", false
}

func npmTarball(path string) (string, bool) {
	name, file, ok := strings.Cut(strings.TrimPrefix(path, "/"), "/-/")
	if !ok || name == "" || !strings.HasSuffix(file, ".tgz") || strings.Contains(file, "/") {
		return "", false
	}
	base := name
	if i := strings.LastIndex(name, "/"); i >= 0 {
		if !strings.HasPrefix(name, "@") || strings.Count(name, "/") != 1 {
			return "", false
		}
		base = name[i+1:]
	}
	v := strings.TrimSuffix(file, ".tgz")
	if !strings.HasPrefix(v, base+"-") {
		return "", false
	}
	v = strings.TrimPrefix(v, base+"-")
	if v == "" {
		return "", false
	}
	return Ref(NPM, name, v), true
}

func pypiFile(path string) (string, bool) {
	if !strings.HasPrefix(path, "/packages/") {
		return "", false
	}
	file := path[strings.LastIndex(path, "/")+1:]
	if strings.HasSuffix(file, ".whl") {
		parts := strings.Split(strings.TrimSuffix(file, ".whl"), "-")
		if len(parts) < 5 { // name-version(-build)-python-abi-platform
			return "", false
		}
		return Ref(PyPI, parts[0], parts[1]), true
	}
	for _, ext := range []string{".tar.gz", ".zip", ".tar.bz2", ".tgz"} {
		if strings.HasSuffix(file, ext) {
			stem := strings.TrimSuffix(file, ext)
			i := strings.LastIndex(stem, "-")
			if i <= 0 || i == len(stem)-1 {
				return "", false
			}
			return Ref(PyPI, stem[:i], stem[i+1:]), true
		}
	}
	return "", false
}

// goZip: /<escaped module>/@v/<version>.zip; "!x" in the path is "X".
func goZip(path string) (string, bool) {
	mod, file, ok := strings.Cut(strings.TrimPrefix(path, "/"), "/@v/")
	if !ok || mod == "" || !strings.HasSuffix(file, ".zip") || strings.Contains(file, "/") {
		return "", false
	}
	var b strings.Builder
	for i := 0; i < len(mod); i++ {
		if mod[i] == '!' && i+1 < len(mod) {
			i++
			b.WriteString(strings.ToUpper(string(mod[i])))
			continue
		}
		b.WriteByte(mod[i])
	}
	return Ref(Go, b.String(), strings.TrimSuffix(file, ".zip")), true
}

func crateFile(path string) (string, bool) {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) != 3 || parts[0] != "crates" || !strings.HasSuffix(parts[2], ".crate") {
		return "", false
	}
	name := parts[1]
	v := strings.TrimSuffix(parts[2], ".crate")
	if !strings.HasPrefix(v, name+"-") {
		return "", false
	}
	return Ref(Crate, name, strings.TrimPrefix(v, name+"-")), true
}
