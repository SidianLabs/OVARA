// Package lockfiles lists the exact packages a project has pinned, so the
// box's strict profile can tell a dependency the project already has from
// one the agent is adding. Each package is named the way the proxy names a
// download it sees (ecosystem:name@version, see Ref), with the digests the
// lockfile records for it, if any, so the proxy can check that what it
// downloads is what was pinned.
//
// Read: npm (package-lock.json, npm-shrinkwrap.json), yarn (yarn.lock, v1
// and berry), pnpm (pnpm-lock.yaml), Python (requirements*.txt pins,
// poetry.lock, uv.lock, Pipfile.lock), Go (go.sum), Rust (Cargo.lock), Ruby
// (Gemfile.lock), Gradle (gradle.lockfile) and PHP (composer.lock, whose
// packages Composer downloads as GitHub archives of one commit, so they are
// pinned as github:owner/repo@commit). Digests come from npm,
// yarn v1 and pnpm integrity, requirements --hash, poetry and uv hashes and
// Cargo checksums. A format it cannot read only means more packages
// pause; it never lets one through.
package lockfiles

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Ecosystems, as they appear in a Ref.
const (
	NPM   = "npm"
	PyPI  = "pypi"
	Go    = "go"
	Crate = "crate"
	Gem   = "gem"
	Maven = "maven"
	// GitHub is a source archive of one commit: what Composer downloads for
	// a Packagist package hosted there (the "dist" in composer.lock)
	GitHub = "github"
)

// Ref names one package version: "npm:left-pad@1.3.0".
func Ref(ecosystem, name, version string) string {
	switch ecosystem {
	case PyPI:
		name = NormalizePyPI(name)
	case GitHub:
		name = strings.ToLower(name) // owner and repository names ignore case
	}
	return ecosystem + ":" + name + "@" + version
}

var pypiSep = regexp.MustCompile(`[-_.]+`)

// NormalizePyPI is PEP 503 name normalisation.
func NormalizePyPI(name string) string {
	return pypiSep.ReplaceAllString(strings.ToLower(name), "-")
}

// skipped directories: dependencies' own lockfiles are not the project's
var skipDirs = map[string]bool{"node_modules": true, ".git": true, ".venv": true, "venv": true, "vendor": true, "target": true, "__pycache__": true}

const maxDepth = 6

// pin is one package a lockfile names, with the digests it records for it
// (Subresource Integrity form: "sha512-<base64>").
type pin struct {
	ref     string
	digests []string
}

// Scan walks the project and returns the sorted, de-duplicated refs of
// every pinned package, and the lockfiles it read (relative paths).
func Scan(root string) (refs, files []string) {
	pins, files := ScanPins(root)
	for r := range pins {
		refs = append(refs, r)
	}
	sort.Strings(refs)
	return refs, files
}

// ScanPins is Scan with each package's recorded digests (SRI form; none
// when the lockfile records none).
func ScanPins(root string) (pins map[string][]string, files []string) {
	pins = map[string][]string{}
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable directory is skipped, not fatal
		}
		rel, _ := filepath.Rel(root, p)
		if d.IsDir() {
			if p != root && (skipDirs[d.Name()] || strings.Count(filepath.ToSlash(rel), "/") >= maxDepth) {
				return filepath.SkipDir
			}
			return nil
		}
		var got []pin
		switch name := d.Name(); {
		case name == "package-lock.json" || name == "npm-shrinkwrap.json":
			got = npmLock(p)
		case name == "yarn.lock":
			got = yarnLock(p)
		case name == "pnpm-lock.yaml":
			got = pnpmLock(p)
		case strings.HasPrefix(name, "requirements") && strings.HasSuffix(name, ".txt"):
			got = requirements(p)
		case name == "poetry.lock" || name == "uv.lock":
			got = tomlPackages(p, PyPI)
		case name == "Cargo.lock":
			got = tomlPackages(p, Crate)
		case name == "Pipfile.lock":
			got = pipfileLock(p)
		case name == "go.sum":
			got = goSum(p)
		case name == "Gemfile.lock":
			got = gemfileLock(p)
		case name == "gradle.lockfile":
			got = gradleLock(p)
		case name == "composer.lock":
			got = composerLock(p)
		default:
			return nil
		}
		files = append(files, filepath.ToSlash(rel))
		for _, g := range got {
			have := pins[g.ref]
			for _, dg := range g.digests {
				if !contains(have, dg) {
					have = append(have, dg)
				}
			}
			pins[g.ref] = have
		}
		return nil
	})
	sort.Strings(files)
	return pins, files
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// FormatPins writes pins the way the proxy's -package-gate file holds
// them: one package per line, its ref, then its digests.
func FormatPins(pins map[string][]string) string {
	refs := make([]string, 0, len(pins))
	for r := range pins {
		refs = append(refs, r)
	}
	sort.Strings(refs)
	var b strings.Builder
	for _, r := range refs {
		b.WriteString(r)
		for _, d := range pins[r] {
			b.WriteByte(' ')
			b.WriteString(d)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// ParsePins reads what FormatPins wrote (a file of bare refs, one per line,
// reads as pins without digests).
func ParsePins(text string) map[string][]string {
	pins := map[string][]string{}
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		pins[f[0]] = append(pins[f[0]], f[1:]...)
	}
	return pins
}

// sriDigests keeps the SRI tokens ("sha512-<base64>") of an integrity
// string with known algorithms.
func sriDigests(integrity string) []string {
	var out []string
	for _, tok := range strings.Fields(integrity) {
		algo, b64, ok := strings.Cut(tok, "-")
		if !ok {
			continue
		}
		if i := strings.IndexByte(b64, '?'); i >= 0 { // SRI options
			b64 = b64[:i]
		}
		switch algo {
		case "sha1", "sha256", "sha384", "sha512":
			if _, err := base64.StdEncoding.DecodeString(b64); err == nil {
				out = append(out, algo+"-"+b64)
			}
		}
	}
	return out
}

// hexDigest turns "sha256:<hex>" (or bare hex with algo given) into SRI form.
func hexDigest(algo, h string) string {
	b, err := hex.DecodeString(strings.ToLower(h))
	if err != nil {
		return ""
	}
	switch {
	case algo == "sha256" && len(b) == 32, algo == "sha384" && len(b) == 48, algo == "sha512" && len(b) == 64:
		return algo + "-" + base64.StdEncoding.EncodeToString(b)
	}
	return ""
}

func npmLock(path string) []pin {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var lock struct {
		Packages map[string]struct {
			Name      string `json:"name"`
			Version   string `json:"version"`
			Link      bool   `json:"link"`
			Integrity string `json:"integrity"`
		} `json:"packages"`
		Dependencies map[string]json.RawMessage `json:"dependencies"`
	}
	if json.Unmarshal(b, &lock) != nil {
		return nil
	}
	out := make([]pin, 0, len(lock.Packages))
	for key, p := range lock.Packages {
		i := strings.LastIndex(key, "node_modules/")
		if key == "" || p.Link || p.Version == "" || i < 0 {
			continue
		}
		name := key[i+len("node_modules/"):]
		if p.Name != "" {
			name = p.Name // an alias: the real package is what is fetched
		}
		out = append(out, pin{Ref(NPM, name, p.Version), sriDigests(p.Integrity)})
	}
	// lockfile v1: a nested "dependencies" tree
	var walk func(map[string]json.RawMessage)
	walk = func(deps map[string]json.RawMessage) {
		for name, raw := range deps {
			var d struct {
				Version      string                     `json:"version"`
				Integrity    string                     `json:"integrity"`
				Dependencies map[string]json.RawMessage `json:"dependencies"`
			}
			if json.Unmarshal(raw, &d) != nil {
				continue
			}
			if d.Version != "" && !strings.Contains(d.Version, ":") {
				out = append(out, pin{Ref(NPM, name, d.Version), sriDigests(d.Integrity)})
			}
			walk(d.Dependencies)
		}
	}
	walk(lock.Dependencies)
	return out
}

var (
	yarnVersion   = regexp.MustCompile(`^\s+version:?\s+"?([^"\s]+)"?`)
	yarnIntegrity = regexp.MustCompile(`^\s+integrity\s+"?([^"\s]+)"?`)
)

// yarn.lock: a block header lists "name@range" specs, then "version" (and
// in v1, "integrity").
func yarnLock(path string) []pin {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []pin
	var names []string
	block := -1 // first pin of the current block in out
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(line, ":") {
			names = names[:0]
			block = -1
			for _, spec := range strings.Split(strings.TrimSuffix(line, ":"), ",") {
				spec = strings.Trim(strings.TrimSpace(spec), `"`)
				if i := strings.LastIndex(spec, "@"); i > 0 {
					names = append(names, spec[:i])
				}
			}
			continue
		}
		if m := yarnVersion.FindStringSubmatch(line); m != nil && len(names) > 0 {
			block = len(out)
			seen := map[string]bool{}
			for _, n := range names {
				if !seen[n] {
					seen[n] = true
					out = append(out, pin{ref: Ref(NPM, n, m[1])})
				}
			}
			names = names[:0]
			continue
		}
		if m := yarnIntegrity.FindStringSubmatch(line); m != nil && block >= 0 {
			for i := block; i < len(out); i++ {
				out[i].digests = append(out[i].digests, sriDigests(m[1])...)
			}
		}
	}
	return out
}

// pnpm-lock.yaml "packages:" keys: v6+ "name@1.2.3" / "/name@1.2.3",
// v5 "/name/1.2.3"; a peer suffix "(...)" or "_..." is dropped.
var (
	pnpmKey       = regexp.MustCompile(`^  '?/?((?:@[^/@\s']+/)?[^/@\s']+)[@/]([0-9][^()_:\s']*)`)
	pnpmIntegrity = regexp.MustCompile(`integrity:\s*([^,}\s]+)`)
)

func pnpmLock(path string) []pin {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []pin
	in := false
	last := -1
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, " ") && line != "" {
			in = line == "packages:" || line == "snapshots:"
			last = -1
			continue
		}
		if !in {
			continue
		}
		if m := pnpmKey.FindStringSubmatch(line); m != nil {
			out = append(out, pin{ref: Ref(NPM, m[1], m[2])})
			last = len(out) - 1
			continue
		}
		if m := pnpmIntegrity.FindStringSubmatch(line); m != nil && last >= 0 && strings.HasPrefix(line, "    ") {
			out[last].digests = append(out[last].digests, sriDigests(m[1])...)
		}
	}
	return out
}

var (
	reqPin  = regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([^\s;#,\\]+)`)
	reqHash = regexp.MustCompile(`--hash[=\s]+(sha256|sha384|sha512):([0-9a-fA-F]+)`)
)

func requirements(path string) []pin {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	// a requirement may go on over lines ending in a backslash
	text := strings.ReplaceAll(strings.ReplaceAll(string(b), "\r\n", "\n"), "\\\n", " ")
	lines := strings.Split(text, "\n")
	out := make([]pin, 0, len(lines))
	for _, line := range lines {
		m := reqPin.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		p := pin{ref: Ref(PyPI, m[1], m[2])}
		for _, h := range reqHash.FindAllStringSubmatch(line, -1) {
			if d := hexDigest(h[1], h[2]); d != "" {
				p.digests = append(p.digests, d)
			}
		}
		out = append(out, p)
	}
	return out
}

var (
	tomlKV   = regexp.MustCompile(`^(name|version|checksum)\s*=\s*"([^"]+)"`)
	tomlHash = regexp.MustCompile(`hash\s*=\s*"(sha256|sha384|sha512):([0-9a-fA-F]+)"`)
)

// poetry.lock, uv.lock and Cargo.lock: [[package]] tables with name and
// version, and the digests of their files (poetry and uv: hash = "sha256:…";
// Cargo: checksum = "<sha256 hex>").
func tomlPackages(path, eco string) []pin {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []pin
	name, version := "", ""
	var digests []string
	flush := func() {
		if name != "" && version != "" {
			out = append(out, pin{Ref(eco, name, version), digests})
		}
		name, version, digests = "", "", nil
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	in := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") && !strings.HasPrefix(line, "[ ") {
			if in {
				flush()
			}
			in = line == "[[package]]"
			continue
		}
		if !in {
			continue
		}
		if m := tomlKV.FindStringSubmatch(line); m != nil {
			switch m[1] {
			case "name":
				name = m[2]
			case "version":
				version = m[2]
			case "checksum":
				if d := hexDigest("sha256", m[2]); d != "" {
					digests = append(digests, d)
				}
			}
			continue
		}
		for _, h := range tomlHash.FindAllStringSubmatch(line, -1) {
			if d := hexDigest(h[1], h[2]); d != "" {
				digests = append(digests, d)
			}
		}
	}
	if in {
		flush()
	}
	return out
}

func pipfileLock(path string) []pin {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var lock map[string]json.RawMessage
	if json.Unmarshal(b, &lock) != nil {
		return nil
	}
	var out []pin
	for _, section := range []string{"default", "develop"} {
		var deps map[string]struct {
			Version string   `json:"version"`
			Hashes  []string `json:"hashes"`
		}
		if json.Unmarshal(lock[section], &deps) != nil {
			continue
		}
		for name, d := range deps {
			if v := strings.TrimPrefix(d.Version, "=="); v != "" && v != d.Version {
				p := pin{ref: Ref(PyPI, name, v)}
				for _, h := range d.Hashes {
					algo, hx, _ := strings.Cut(h, ":")
					if dg := hexDigest(algo, hx); dg != "" {
						p.digests = append(p.digests, dg)
					}
				}
				out = append(out, p)
			}
		}
	}
	return out
}

// go.sum's h1: hashes are of the module's file tree, not of the zip the
// proxy serves, so Go pins carry no digest.
func goSum(path string) []pin {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []pin
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		v := strings.TrimSuffix(fields[1], "/go.mod")
		out = append(out, pin{ref: Ref(Go, fields[0], v)})
	}
	return out
}

// Gemfile.lock: under GEM, "specs:" lists "    name (version)" (a
// platform gem's version carries its platform: "1.15.4-x86_64-linux").
var gemSpec = regexp.MustCompile(`^    ([A-Za-z0-9][A-Za-z0-9._-]*) \(([0-9][^)\s]*)\)$`)

func gemfileLock(path string) []pin {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []pin
	section := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line != "" && !strings.HasPrefix(line, " ") {
			section = line
			continue
		}
		if section != "GEM" {
			continue
		}
		if m := gemSpec.FindStringSubmatch(line); m != nil {
			out = append(out, pin{ref: Ref(Gem, m[1], m[2])})
		}
	}
	return out
}

// gradle.lockfile: "group:artifact:version=configurations"
func gradleLock(path string) []pin {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []pin
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "empty=") {
			continue
		}
		coord, _, _ := strings.Cut(line, "=")
		parts := strings.Split(coord, ":")
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
			continue
		}
		out = append(out, pin{ref: Ref(Maven, parts[0]+":"+parts[1], parts[2])})
	}
	return out
}

// composer.lock: "packages" and "packages-dev", each with the archive
// ("dist") Composer downloads and the commit ("source") it was made from.
// A GitHub-hosted package is pinned at its commit, so a tag moved to other
// code afterwards names a commit the lockfile does not have. Packages
// hosted elsewhere are not named here; their downloads are not a registry
// the proxy names either.
func composerLock(path string) []pin {
	b, err := os.ReadFile(path) //nolint:gosec // a lockfile in the project
	if err != nil {
		return nil
	}
	type pkg struct {
		Dist struct {
			URL       string `json:"url"`
			Reference string `json:"reference"`
		} `json:"dist"`
		Source struct {
			URL       string `json:"url"`
			Reference string `json:"reference"`
		} `json:"source"`
	}
	var lock struct {
		Packages    []pkg `json:"packages"`
		PackagesDev []pkg `json:"packages-dev"`
	}
	if json.Unmarshal(b, &lock) != nil {
		return nil
	}
	var out []pin
	for _, p := range append(lock.Packages, lock.PackagesDev...) {
		if u, err := url.Parse(p.Dist.URL); err == nil {
			if k, ref := Classify(u.Host, u.Path); k == Artifact {
				out = append(out, pin{ref: ref})
				continue
			}
		}
		if repo, ok := githubRepoURL(p.Source.URL); ok && commitRef.MatchString(p.Source.Reference) {
			out = append(out, pin{ref: Ref(GitHub, repo, p.Source.Reference)})
		}
	}
	return out
}

// commitRef is a full git commit id.
var commitRef = regexp.MustCompile(`^[0-9a-f]{40}$`)

// githubRepoURL returns owner/repo of a github.com clone URL.
func githubRepoURL(s string) (string, bool) {
	u, err := url.Parse(s)
	if err != nil || !strings.EqualFold(u.Host, "github.com") {
		return "", false
	}
	parts := strings.Split(strings.TrimSuffix(strings.Trim(u.Path, "/"), ".git"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", false
	}
	return parts[0] + "/" + parts[1], true
}
