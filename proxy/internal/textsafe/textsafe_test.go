package textsafe

import "testing"

func TestKindsAndHidden(t *testing.T) {
	cases := map[rune]string{
		0x1B: KindControl, 0x202E: KindBidi, 0x2067: KindBidi, 0x200B: KindZeroWidth,
		0xFEFF: KindZeroWidth, 0xE0041: KindTag, 0xFE0F: KindVariation, 0x3164: KindFiller,
		0x2028: KindSeparator, 0x00AD: KindFormat, 'a': "", 0x00E9: "", 0x4E2D: "",
	}
	for r, want := range cases {
		if got := Kind(r); got != want {
			t.Errorf("Kind(%U) = %q, want %q", r, got, want)
		}
	}
	s := "ok\tline\n" + string(rune(0xE0041)) + string(rune(0xE0042)) + string(rune(0x202E))
	h := Hidden(s)
	if h[KindTag] != 2 || h[KindBidi] != 1 || len(h) != 2 {
		t.Fatalf("Hidden = %v (tab and newline are layout, not hidden)", h)
	}
	if got := Escape("a" + string(rune(0x202E)) + "b\n"); got != `a\u{202E}b ⏎ ` {
		t.Fatalf("Escape = %q", got)
	}
}
