package boxgate

import "strings"

// PolicyLine is the command line policy rules are matched against: the
// same exec as CommandLine, put in one canonical spelling so that a rule
// like "*rm -rf*" or "*git push*" is not dodged by writing the command
// differently. The person approving still sees the raw CommandLine.
//
//   - the program is its base name ("/usr/bin/sudo" reads "sudo");
//   - git's global options before the subcommand are dropped
//     ("git -c k=v -C dir push" reads "git push"), and an alias given with
//     -c is replaced by what it stands for;
//   - rm's flags are merged into one group with r and f first, wherever
//     they stand ("rm -r -f x", "rm --recursive --force x" and "rm x -Rf"
//     all read "rm -rf x");
//   - runs of white space are one space.
//
// This is not a shell parser. A shell's -c line is only tidied, because
// the programs it starts are stopped at their own exec and judged as
// themselves: `sh -c "rm -r -f x"` is checked once as the shell line and
// again as rm. What normalising cannot see: a renamed copy of a program, a
// git alias defined in a config file, or a script that deletes files
// itself; the default shell rules catch mistakes, they do not contain an
// agent that is trying to get around them.
func PolicyLine(e Exec) string {
	if len(e.Argv) == 0 {
		return e.Exe
	}
	name := baseName(e.Argv[0])
	if shells[name] {
		if line, ok := shellScript(e.Argv); ok {
			return strings.Join(strings.Fields(line), " ")
		}
	}
	args := e.Argv[1:]
	switch name {
	case "git":
		args = gitArgs(args)
	case "rm":
		args = rmArgs(args)
	}
	return strings.Join(strings.Fields(strings.Join(append([]string{name}, args...), " ")), " ")
}

func baseName(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// shellScript returns the -c string of a shell's argv.
func shellScript(argv []string) (string, bool) {
	for i := 1; i < len(argv)-1; i++ {
		if argv[i] == "-c" {
			return argv[i+1], true
		}
		if !strings.HasPrefix(argv[i], "-") {
			break
		}
	}
	return "", false
}

// gitOptsWithValue are git's global options that take the next argument.
var gitOptsWithValue = map[string]bool{
	"-c": true, "-C": true, "--git-dir": true, "--work-tree": true,
	"--namespace": true, "--config-env": true, "--super-prefix": true,
}

// gitArgs drops git's global options and resolves a -c alias for the
// subcommand.
func gitArgs(args []string) []string {
	aliases := map[string]string{}
	i := 0
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		a := args[i]
		if a == "--" {
			i++
			break
		}
		if gitOptsWithValue[a] && i+1 < len(args) {
			if a == "-c" {
				addAlias(aliases, args[i+1])
			}
			i += 2
			continue
		}
		if v, ok := strings.CutPrefix(a, "-c"); ok && v != "" && a != "-c" && !strings.HasPrefix(a, "--") {
			addAlias(aliases, v) // -ckey=value
		}
		i++ // --git-dir=x, --no-pager, -P, --bare, ...
	}
	rest := args[i:]
	if len(rest) > 0 {
		if expansion, ok := aliases[strings.ToLower(rest[0])]; ok {
			expansion = strings.TrimPrefix(expansion, "!") // a shell alias runs its own execs anyway
			rest = append(strings.Fields(expansion), rest[1:]...)
		}
	}
	return rest
}

func addAlias(aliases map[string]string, kv string) {
	k, v, _ := strings.Cut(kv, "=")
	if name, ok := strings.CutPrefix(strings.ToLower(k), "alias."); ok {
		aliases[name] = v
	}
}

// rmArgs merges rm's options into one group: r (also -R, --recursive) and
// f (--force) first, then any other short letters, then other long
// options, then the operands. GNU rm takes options anywhere before "--".
func rmArgs(args []string) []string {
	var r, f bool
	var letters, long, operands []string
	seen := map[rune]bool{}
	for i, a := range args {
		if a == "--" {
			operands = append(operands, args[i+1:]...)
			break
		}
		switch {
		case a == "--recursive":
			r = true
		case a == "--force":
			f = true
		case strings.HasPrefix(a, "--"):
			long = append(long, a)
		case strings.HasPrefix(a, "-") && len(a) > 1:
			for _, c := range a[1:] {
				switch c {
				case 'r', 'R':
					r = true
				case 'f':
					f = true
				default:
					if !seen[c] {
						seen[c] = true
						letters = append(letters, string(c))
					}
				}
			}
		default:
			operands = append(operands, a)
		}
	}
	flags := ""
	if r {
		flags += "r"
	}
	if f {
		flags += "f"
	}
	flags += strings.Join(letters, "")
	var out []string
	if flags != "" {
		out = append(out, "-"+flags)
	}
	out = append(out, long...)
	return append(out, operands...)
}
