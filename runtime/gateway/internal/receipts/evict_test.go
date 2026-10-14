package receipts

import (
	"fmt"
	"testing"
	"time"

	"ovara.runtime.gateway/internal/models"
)

// G-12: evicting the oldest receipt must not cost a sort of the whole
// store under the lock (it took ~335 ms at 10k receipts, which turned a
// receipts_max_size into a decision-throughput limit). It must still
// evict the oldest first.
func TestEvictionIsCheapAndOldestFirst(t *testing.T) {
	s := &FileBackedStore{receipts: map[string]*models.Receipt{}, maxSize: 10000}
	base := time.Now()
	for i := 0; i < 10001; i++ {
		s.add(&models.Receipt{ReceiptID: fmt.Sprintf("r%05d", i), IssuedAt: base.Add(time.Duration(i) * time.Millisecond)})
	}
	start := time.Now()
	for k := 0; k < 100; k++ {
		s.evictOldest(1)
		s.add(&models.Receipt{ReceiptID: fmt.Sprintf("n%05d", k)})
	}
	if el := time.Since(start); el > 50*time.Millisecond {
		t.Fatalf("100 evictions at 10k receipts took %v", el)
	}
	for i := 0; i < 100; i++ {
		if _, ok := s.receipts[fmt.Sprintf("r%05d", i)]; ok {
			t.Fatalf("r%05d should have been evicted first", i)
		}
	}
	if _, ok := s.receipts["r00100"]; !ok {
		t.Fatal("evicted more than the oldest")
	}
	if len(s.receipts) != 10001 {
		t.Fatalf("store holds %d", len(s.receipts))
	}
}
