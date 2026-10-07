package flock

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Two handles on one file must serialize: the second Lock blocks until the
// first Unlock.
func TestLockSerializesHandles(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	a, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := os.OpenFile(p, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	if err := Lock(a); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	acquired := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := Lock(b); err != nil {
			t.Error(err)
			return
		}
		close(acquired)
		_ = Unlock(b)
	}()

	select {
	case <-acquired:
		t.Fatal("second handle acquired the lock while the first still held it")
	case <-time.After(150 * time.Millisecond):
	}
	if err := Unlock(a); err != nil {
		t.Fatal(err)
	}
	select {
	case <-acquired:
	case <-time.After(3 * time.Second):
		t.Fatal("second handle never acquired the lock after release")
	}
	wg.Wait()
}
