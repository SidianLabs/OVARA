package server

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"ovara.runtime.gateway/internal/anchor"
)

type fakePusher struct{ err error }

func (f fakePusher) Commit(context.Context, string, *anchor.Checkpoint) error { return f.err }

// F-D1: degraded mode may swallow oracle UNAVAILABILITY but must never
// mask integrity signals — equivocation, bad lineage key, malformed
// responses all propagate and fail the mutation.
func TestWarnPusherSwallowsOnlyUnavailability(t *testing.T) {
	cp := &anchor.Checkpoint{}
	for name, err := range map[string]error{
		"unavailable":            fmt.Errorf("dial: %w", anchor.ErrUnavailable),
		"timeout-as-unavailable": anchor.ErrUnavailable,
	} {
		if gerr := (&warnPusher{inner: fakePusher{err}}).Commit(context.Background(), "d", cp); gerr != nil {
			t.Fatalf("%s should degrade to warning, got %v", name, gerr)
		}
	}
	for name, err := range map[string]error{
		"equivocation": fmt.Errorf("%w: fork", anchor.ErrEquivocation),
		"bad-key":      fmt.Errorf("%w", anchor.ErrBadKey),
		"regression":   fmt.Errorf("%w", anchor.ErrRegression),
		"malformed":    fmt.Errorf("%w", anchor.ErrBadResponse),
		"unregistered": fmt.Errorf("%w", anchor.ErrDomainUnregistered),
		"pin-mismatch": fmt.Errorf("%w", anchor.ErrPinMismatch),
	} {
		if gerr := (&warnPusher{inner: fakePusher{err}}).Commit(context.Background(), "d", cp); !errors.Is(gerr, err) {
			t.Fatalf("%s must propagate, got %v", name, gerr)
		}
	}
}
