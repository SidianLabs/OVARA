package boxgate

import (
	"strings"
	"testing"
)

// rmRecursiveForce is the oracle: whether GNU rm, given these arguments,
// deletes recursively and without asking. Options count up to "--"; a
// short group sets every letter in it; a long option may be abbreviated.
func rmRecursiveForce(args []string) bool {
	var r, f bool
	for _, a := range args {
		if a == "--" {
			break
		}
		switch {
		case strings.HasPrefix(a, "--"):
			// a is an abbreviation of the option: the option starts with it
			const recursive, force = "--recursive", "--force"
			if len(a) > 2 && strings.HasPrefix(recursive, a) {
				r = true
			}
			if len(a) > 2 && strings.HasPrefix(force, a) {
				f = true
			}
		case strings.HasPrefix(a, "-") && len(a) > 1:
			r = r || strings.ContainsAny(a[1:], "rR")
			f = f || strings.Contains(a[1:], "f")
		}
	}
	return r && f
}

// Policy rules are written against PolicyLine. Whatever an exec's argv
// holds it never panics, and every recursive forced rm reads "rm -rf",
// however its flags are spelled or where they stand, and whatever argv[0]
// claims when the image is rm.
func FuzzPolicyLine(f *testing.F) {
	for _, s := range [][2]string{
		{"rm", "-rf\x00x"}, {"/bin/rm", "-r\x00-f\x00x"}, {"rm", "--recursive\x00--force\x00x"},
		{"rm", "x\x00-R\x00-v\x00-f"}, {"rm", "--rec\x00--for\x00x"}, {"notrm", "-rf\x00/"},
		{"rm", "-r\x00--\x00-f"}, {"git", "-c\x00alias.x=push --force\x00x"}, {"sh", "-c\x00rm -r -f x"},
		{"", ""}, {"/", "\x00\x00"},
	} {
		f.Add(s[0], s[1], false)
		f.Add(s[0], s[1], true)
	}
	f.Fuzz(func(t *testing.T, argv0, rest string, exeIsRm bool) {
		argv := []string{argv0}
		if rest != "" {
			argv = append(argv, strings.Split(rest, "\x00")...)
		}
		e := Exec{Exe: "/usr/bin/" + baseName(argv0), Argv: argv}
		if exeIsRm {
			e.Exe = "/usr/bin/rm"
		}
		line := PolicyLine(e)
		_ = PolicyLine(Exec{Exe: rest})
		isRm := exeIsRm || baseName(argv0) == "rm"
		if isRm && rmRecursiveForce(argv[1:]) && !strings.HasPrefix(line, "rm -rf") {
			t.Fatalf("%q (image %s) reads %q", argv, e.Exe, line)
		}
	})
}
