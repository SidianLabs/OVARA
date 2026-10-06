package decide

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// ReplayStore makes the nonce guard durable — without it a restart
// inside the freshness window re-admits a replayed signed request
// (the signature is still valid; only the seen-set stood in the way).
type ReplayStore struct {
	mu   sync.Mutex
	path string
	f    *os.File
	seen map[string]time.Time
}

type replayRow struct {
	Nonce string `json:"nonce"`
	At    int64  `json:"at"` // unix nanos of first use
}

// OpenReplayStore loads nonces within the freshness horizon and
// appends new ones. Corrupt tail lines fail closed (refuse to open —
// a truncated store must not silently drop its contents).
func OpenReplayStore(path string, horizon time.Duration) (*ReplayStore, error) {
	s := &ReplayStore{path: path, seen: map[string]time.Time{}}
	if data, err := os.ReadFile(path); err == nil {
		sc := bufio.NewScanner(bytes.NewReader(data))
		for sc.Scan() {
			var r replayRow
			if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
				return nil, fmt.Errorf("replay store corrupt: %w", err)
			}
			at := time.Unix(0, r.At)
			if time.Since(at) < horizon*2 {
				s.seen[r.Nonce] = at
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	s.f = f
	return s, nil
}

// Seen reports whether nonce was already used; if not, records it
// durably BEFORE returning (write-ahead — a crash between record and
// decision must keep the nonce dead).
func (s *ReplayStore) Seen(nonce string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.seen[nonce]; ok {
		return true, nil
	}
	at := time.Now().UTC()
	row, _ := json.Marshal(replayRow{Nonce: nonce, At: at.UnixNano()})
	if _, err := s.f.Write(append(row, '\n')); err != nil {
		return false, fmt.Errorf("replay store write: %w", err)
	}
	if err := s.f.Sync(); err != nil {
		return false, fmt.Errorf("replay store sync: %w", err)
	}
	s.seen[nonce] = at
	return false, nil
}

func (s *ReplayStore) Close() error { return s.f.Close() }
