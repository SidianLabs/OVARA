// Package lockfiles lists the exact packages a project has pinned, so the
// box's strict profile can tell a dependency the project already has from
// one the agent is adding. Each package is named the way the proxy names a
// download it sees (ecosystem:name@version, see Ref).
//
// Read: npm (package-lock.json, npm-shrinkwrap.json), yarn (yarn.lock, v1
// and berry), pnpm (pnpm-lock.yaml), Python (requirements*.txt pins,
// poetry.lock, uv.lock, Pipfile.lock), Go (go.sum) and Rust (Cargo.lock).
// A format it cannot read only means more packages pause; it never lets
// one through.
package lockfiles

import (
	"bufio"
	"encoding/json"
	"io/fs"
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
)

// Ref names one package version: "npm:left-pad@1.3.0".
func Ref(ecosystem, name, version string) string {
	if ecosystem == PyPI {
		name = NormalizePyPI(name)
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

// Scan walks the project and returns the sorted, de-duplicated refs of
// every pinned package, and the lockfiles it read (relative paths).
func Scan(root string) (refs, files []string) {
	set := map[string]bool{}
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
		var got []string
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
		default:
			return nil
		}
		files = append(files, filepath.ToSlash(rel))
		for _, r := range got {
			set[r] = true
		}
		return nil
	})
	for r := range set {
		refs = append(refs, r)
	}
	sort.Strings(refs)
	sort.Strings(files)
	return refs, files
}

func npmLock(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var lock struct {
		Packages map[string]struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Link    bool   `json:"link"`
		} `json:"packages"`
		Dependencies map[string]json.RawMessage `json:"dependencies"`
	}
	if json.Unmarshal(b, &lock) != nil {
		return nil
	}
	var out []string
	for key, p := range lock.Packages {
		i := strings.LastIndex(key, "node_modules/")
		if key == "" || p.Link || p.Version == "" || i < 0 {
			continue
		}
		name := key[i+len("node_modules/"):]
		if p.Name != "" {
			name = p.Name // an alias: the real package is what is fetched
		}
		out = append(out, Ref(NPM, name, p.Version))
	}
	// lockfile v1: a nested "dependencies" tree
	var walk func(map[string]json.RawMessage)
	walk = func(deps map[string]json.RawMessage) {
		for name, raw := range deps {
			var d struct {
				Version      string                     `json:"version"`
				Dependencies map[string]json.RawMessage `json:"dependencies"`
			}
			if json.Unmarshal(raw, &d) != nil {
				continue
			}
			if d.Version != "" && !strings.Contains(d.Version, ":") {
				out = append(out, Ref(NPM, name, d.Version))
			}
			walk(d.Dependencies)
		}
	}
	walk(lock.Dependencies)
	return out
}

var yarnVersion = regexp.MustCompile(`^\s+version:?\s+"?([^"\s]+)"?`)

// yarn.lock: a block header lists "name@range" specs, then "version".
func yarnLock(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out, names []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(line, ":") {
			names = names[:0]
			for _, spec := range strings.Split(strings.TrimSuffix(line, ":"), ",") {
				spec = strings.Trim(strings.TrimSpace(spec), `"`)
				if i := strings.LastIndex(spec, "@"); i > 0 {
					names = append(names, spec[:i])
				}
			}
			continue
		}
		if m := yarnVersion.FindStringSubmatch(line); m != nil && len(names) > 0 {
			seen := map[string]bool{}
			for _, n := range names {
				if !seen[n] {
					seen[n] = true
					out = append(out, Ref(NPM, n, m[1]))
				}
			}
			names = names[:0]
		}
	}
	return out
}

// pnpm-lock.yaml "packages:" keys: v6+ "name@1.2.3" / "/name@1.2.3",
// v5 "/name/1.2.3"; a peer suffix "(...)" or "_..." is dropped.
var pnpmKey = regexp.MustCompile(`^  '?/?((?:@[^/@\s']+/)?[^/@\s']+)[@/]([0-9][^()_:\s']*)`)

func pnpmLock(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	in := false
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, " ") && line != "" {
			in = line == "packages:" || line == "snapshots:"
			continue
		}
		if !in {
			continue
		}
		if m := pnpmKey.FindStringSubmatch(line); m != nil {
			out = append(out, Ref(NPM, m[1], m[2]))
		}
	}
	return out
}

var reqPin = regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([^\s;#,]+)`)

func requirements(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if m := reqPin.FindStringSubmatch(sc.Text()); m != nil {
			out = append(out, Ref(PyPI, m[1], m[2]))
		}
	}
	return out
}

var tomlKV = regexp.MustCompile(`^(name|version)\s*=\s*"([^"]+)"`)

// poetry.lock, uv.lock and Cargo.lock: [[package]] tables with name and version.
func tomlPackages(path, eco string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	name, version := "", ""
	flush := func() {
		if name != "" && version != "" {
			out = append(out, Ref(eco, name, version))
		}
		name, version = "", ""
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	in := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
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
			if m[1] == "name" {
				name = m[2]
			} else {
				version = m[2]
			}
		}
	}
	if in {
		flush()
	}
	return out
}

func pipfileLock(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var lock map[string]json.RawMessage
	if json.Unmarshal(b, &lock) != nil {
		return nil
	}
	var out []string
	for _, section := range []string{"default", "develop"} {
		var deps map[string]struct {
			Version string `json:"version"`
		}
		if json.Unmarshal(lock[section], &deps) != nil {
			continue
		}
		for name, d := range deps {
			if v := strings.TrimPrefix(d.Version, "=="); v != "" && v != d.Version {
				out = append(out, Ref(PyPI, name, v))
			}
		}
	}
	return out
}

func goSum(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		v := strings.TrimSuffix(fields[1], "/go.mod")
		out = append(out, Ref(Go, fields[0], v))
	}
	return out
}
