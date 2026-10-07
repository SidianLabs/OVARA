//go:build !linux

package contain

type noneBackend struct{}

func (noneBackend) Name() string             { return "none" }
func (noneBackend) Available() bool          { return false }
func (noneBackend) ApplyFS(_ []string) error { return ErrUnsupported }

func newBackend() Enforcement { return noneBackend{} }
