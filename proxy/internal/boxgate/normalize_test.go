package boxgate

import "testing"

func TestPolicyLine(t *testing.T) {
	cases := []struct {
		argv []string
		want string
	}{
		// the program by its base name
		{[]string{"/usr/bin/sudo", "id"}, "sudo id"},
		// rm, however its flags are spelled
		{[]string{"rm", "-rf", "x"}, "rm -rf x"},
		{[]string{"rm", "-r", "-f", "x"}, "rm -rf x"},
		{[]string{"/bin/rm", "--recursive", "--force", "x"}, "rm -rf x"},
		{[]string{"rm", "-Rf", "x"}, "rm -rf x"},
		{[]string{"rm", "-fR", "x"}, "rm -rf x"},
		{[]string{"rm", "x", "-r", "-v", "-f"}, "rm -rfv x"},
		{[]string{"rm", "-i", "-r", "x"}, "rm -ri x"},
		{[]string{"rm", "-r", "--", "-f"}, "rm -r -f"}, // after "--", "-f" is a file name
		{[]string{"rm", "x"}, "rm x"},
		// git without its global options
		{[]string{"git", "-c", "user.name=x", "push"}, "git push"},
		{[]string{"git", "-C", "/w", "--no-pager", "-P", "push", "origin", "main"}, "git push origin main"},
		{[]string{"/usr/bin/git", "--git-dir=/w/.git", "--work-tree=/w", "push"}, "git push"},
		{[]string{"git", "-c", "alias.ship=push --force", "ship", "origin"}, "git push --force origin"},
		{[]string{"git", "status"}, "git status"},
		// a shell's -c line, tidied
		{[]string{"/bin/bash", "-c", "rm   -rf\t/tmp/x"}, "rm -rf /tmp/x"},
		{[]string{"sh", "-c", "a && b"}, "a && b"},
		// anything else: just white space
		{[]string{"find", ".", "-name", "*.o", "-delete"}, "find . -name *.o -delete"},
		{[]string{"python3", "-c", "print( 1 )"}, "python3 -c print( 1 )"},
	}
	for _, c := range cases {
		if got := PolicyLine(Exec{Argv: c.argv}); got != c.want {
			t.Errorf("%q: %q, want %q", c.argv, got, c.want)
		}
	}
	if got := PolicyLine(Exec{Exe: "/bin/true"}); got != "/bin/true" {
		t.Errorf("no argv: %q", got)
	}
}
