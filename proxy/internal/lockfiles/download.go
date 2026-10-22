package lockfiles

import (
	"net/url"
	"regexp"
	"strings"
)

// Kind is what a request to a package registry is.
type Kind int

const (
	// NotRegistry: the host is not one of the registries named here.
	NotRegistry Kind = iota
	// Metadata: an index, a packument, a checksum or signature, an API
	// call: not code.
	Metadata
	// Artifact: the download of one package version's code, named by a Ref.
	Artifact
	// Unrecognised: on a registry host, but neither metadata nor an
	// artifact this package can name. The strict profile asks about it
	// rather than let it through unnamed.
	Unrecognised
)

// Classify says what a request to host/path is. For an Artifact it also
// returns the package's Ref, named like Scan names it:
//
//	registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz          npm:left-pad@1.3.0
//	registry.npmjs.org/@types/node/-/node-20.1.0.tgz          npm:@types/node@20.1.0
//	files.pythonhosted.org/packages/../six-1.16.0-py2.py3-none-any.whl   pypi:six@1.16.0
//	files.pythonhosted.org/packages/../Django-4.2.tar.gz      pypi:django@4.2
//	proxy.golang.org/github.com/!foo/bar/@v/v1.2.3.zip        go:github.com/Foo/bar@v1.2.3
//	static.crates.io/crates/serde/serde-1.0.200.crate         crate:serde@1.0.200
//	crates.io/api/v1/crates/serde/1.0.200/download            crate:serde@1.0.200
//	rubygems.org/gems/rails-7.1.0.gem                         gem:rails@7.1.0
//	repo1.maven.org/maven2/org/slf4j/slf4j-api/2.0.9/slf4j-api-2.0.9.jar   maven:org.slf4j:slf4j-api@2.0.9
//	api.github.com/repos/laravel/framework/zipball/<commit>  github:laravel/framework@<commit>
//	codeload.github.com/laravel/framework/legacy.zip/<commit> github:laravel/framework@<commit>
//
// The GitHub API is not a registry: only its archive downloads are named,
// every other path of it is NotRegistry.
func Classify(host, path string) (Kind, string) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if p, err := url.PathUnescape(path); err == nil {
		path = p
	}
	switch host {
	case "registry.npmjs.org", "registry.yarnpkg.com":
		if ref, ok := npmTarball(path); ok {
			return Artifact, ref
		}
		// /-/... is the registry's API (search, audit, whoami); a
		// package's own /-/ is where its tarballs are
		if strings.HasPrefix(path, "/-/") || !strings.Contains(path, "/-/") {
			return Metadata, ""
		}
		return Unrecognised, ""
	case "files.pythonhosted.org":
		if ref, ok := pypiFile(path); ok {
			return Artifact, ref
		}
		if strings.HasPrefix(path, "/packages/") && hasSuffix(path, ".metadata", ".asc") {
			return Metadata, "" // PEP 658 metadata, signatures
		}
		return Unrecognised, ""
	case "proxy.golang.org":
		if ref, ok := goZip(path); ok {
			return Artifact, ref
		}
		if strings.HasPrefix(path, "/sumdb/") || strings.HasSuffix(path, "/@latest") || (strings.Contains(path, "/@v/") && hasSuffix(path, "/list", ".info", ".mod")) {
			return Metadata, ""
		}
		return Unrecognised, ""
	case "static.crates.io":
		if ref, ok := crateFile(path); ok {
			return Artifact, ref
		}
		return Unrecognised, ""
	case "crates.io":
		if ref, ok := crateAPIDownload(path); ok {
			return Artifact, ref
		}
		if strings.HasSuffix(path, "/download") {
			return Unrecognised, ""
		}
		return Metadata, "" // the API and the site
	case "index.crates.io":
		if crateIndex.MatchString(path) {
			return Metadata, ""
		}
		return Unrecognised, ""
	case "rubygems.org", "index.rubygems.org":
		if ref, ok := gemFile(path); ok {
			return Artifact, ref
		}
		if gemMetadata.MatchString(path) {
			return Metadata, ""
		}
		return Unrecognised, ""
	case "repo1.maven.org", "repo.maven.apache.org":
		return mavenPath(path)
	case "api.github.com":
		// /repos/<owner>/<repo>/(zipball|tarball)/<ref>
		parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 5)
		if len(parts) == 5 && parts[0] == "repos" && (parts[3] == "zipball" || parts[3] == "tarball") && parts[1] != "" && parts[2] != "" && parts[4] != "" {
			return Artifact, Ref(GitHub, parts[1]+"/"+parts[2], parts[4])
		}
		return NotRegistry, ""
	case "codeload.github.com":
		// /<owner>/<repo>/(legacy.zip|zip|legacy.tar.gz|tar.gz)/<ref>
		parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 4)
		if len(parts) == 4 && parts[0] != "" && parts[1] != "" && parts[3] != "" {
			switch parts[2] {
			case "legacy.zip", "zip", "legacy.tar.gz", "tar.gz":
				return Artifact, Ref(GitHub, parts[0]+"/"+parts[1], parts[3])
			}
		}
		return Unrecognised, ""
	case "repo.packagist.org", "packagist.org":
		return Metadata, "" // Composer's package index; the code comes from the dist URL
	}
	return NotRegistry, ""
}

// Download names the package artifact a request downloads, if it is one
// (Classify's Artifact).
func Download(host, path string) (string, bool) {
	k, ref := Classify(host, path)
	return ref, k == Artifact
}

func hasSuffix(s string, suffixes ...string) bool {
	for _, x := range suffixes {
		if strings.HasSuffix(s, x) {
			return true
		}
	}
	return false
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

// crateAPIDownload: /api/v1/crates/<name>/<version>/download
func crateAPIDownload(path string) (string, bool) {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) != 6 || parts[0] != "api" || parts[1] != "v1" || parts[2] != "crates" || parts[5] != "download" || parts[3] == "" || parts[4] == "" {
		return "", false
	}
	return Ref(Crate, parts[3], parts[4]), true
}

// the sparse index: /config.json, /1/a, /2/ab, /3/a/abc, /se/rd/serde
var crateIndex = regexp.MustCompile(`^/(?:config\.json|1/[^/]+|2/[^/]+|3/[^/]/[^/]+|[^/]{2}/[^/]{2}/[^/]+)$`)

// gemFile: /gems/<name>-<version>[-<platform>].gem or /downloads/... The
// version is the first dash-separated part that starts with a digit; what
// follows it (a platform) is part of the version, as in Gemfile.lock.
func gemFile(path string) (string, bool) {
	dir, file, ok := strings.Cut(strings.TrimPrefix(path, "/"), "/")
	if !ok || (dir != "gems" && dir != "downloads") || strings.Contains(file, "/") || !strings.HasSuffix(file, ".gem") {
		return "", false
	}
	parts := strings.Split(strings.TrimSuffix(file, ".gem"), "-")
	for i := 1; i < len(parts); i++ {
		if parts[i] != "" && parts[i][0] >= '0' && parts[i][0] <= '9' {
			return Ref(Gem, strings.Join(parts[:i], "-"), strings.Join(parts[i:], "-")), true
		}
	}
	return "", false
}

// rubygems.org's indexes, API and web pages (a gem's page is /gems/<name>,
// without .gem)
var gemMetadata = regexp.MustCompile(`^/(?:$|api/|info/|versions$|names$|(?:latest_|prerelease_)?specs\.[0-9.]+(?:\.gz)?$|quick/|gems/[^/]+(?:/versions(?:/[^/]+)?)?$|search)`)

// mavenPath: /maven2/<group path>/<artifact>/<version>/<artifact>-<version>[-<classifier>].<ext>
func mavenPath(path string) (Kind, string) {
	p := strings.TrimPrefix(path, "/maven2")
	if strings.HasSuffix(p, "/") || hasSuffix(p, "/maven-metadata.xml", ".sha1", ".sha256", ".sha512", ".md5", ".asc") {
		return Metadata, "" // directory listings, metadata, checksums, signatures
	}
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	if len(parts) < 4 {
		return Unrecognised, ""
	}
	n := len(parts)
	file, version, artifact := parts[n-1], parts[n-2], parts[n-3]
	group := strings.Join(parts[:n-3], ".")
	if version == "" || artifact == "" || !strings.HasPrefix(file, artifact+"-"+version) {
		return Unrecognised, ""
	}
	rest := strings.TrimPrefix(file, artifact+"-"+version)
	if (rest != "" && rest[0] != '.' && rest[0] != '-') || !hasSuffix(rest, ".jar", ".pom", ".war", ".aar", ".module", ".zip", ".tar.gz", ".klib") {
		return Unrecognised, ""
	}
	return Artifact, Ref(Maven, group+":"+artifact, version)
}
