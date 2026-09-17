package proxy

import (
	"fmt"
	"strings"
	"testing"
)

func pkt(payload string) string {
	return fmt.Sprintf("%04x%s", len(payload)+4, payload)
}

var shaA = strings.Repeat("a", 40)
var shaB = strings.Repeat("b", 40)
var shaZ = strings.Repeat("0", 40)

func TestParseRefUpdates(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []RefUpdate
	}{
		{
			name: "single update",
			body: pkt(shaA+" "+shaB+" refs/heads/main\x00 report-progress\n") + "0000",
			want: []RefUpdate{{Ref: "refs/heads/main", OldSHA: shaA, NewSHA: shaB}},
		},
		{
			name: "multi update with delete",
			body: pkt(shaA+" "+shaB+" refs/heads/main\x00 report-progress\n") +
				pkt(shaB+" "+shaZ+" refs/heads/old\n") + "0000PACKDATA",
			want: []RefUpdate{
				{Ref: "refs/heads/main", OldSHA: shaA, NewSHA: shaB},
				{Ref: "refs/heads/old", OldSHA: shaB, NewSHA: shaZ, Delete: true},
			},
		},
		{name: "empty", body: "", want: nil},
		{name: "garbage", body: "not pkt-lines at all", want: nil},
		{name: "truncated", body: pkt(shaA + " " + shaB + " refs/heads/main")[:10], want: nil},
		{name: "no flush, pack follows", body: pkt(shaA+" "+shaB+" refs/heads/x\n") + "PACK", want: []RefUpdate{{Ref: "refs/heads/x", OldSHA: shaA, NewSHA: shaB}}},
	}
	for _, tt := range tests {
		got := parseRefUpdates([]byte(tt.body))
		if len(got) != len(tt.want) {
			t.Fatalf("%s: got %d refs %+v, want %d", tt.name, len(got), got, len(tt.want))
		}
		for i, u := range got {
			if u != tt.want[i] {
				t.Errorf("%s: ref %d = %+v, want %+v", tt.name, i, u, tt.want[i])
			}
		}
	}
}
