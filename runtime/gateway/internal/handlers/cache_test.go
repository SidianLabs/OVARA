package handlers

import (
	"testing"
	"time"

	"ovara.runtime.gateway/internal/models"
)

func TestDecisionCache_TTLExpiration(t *testing.T) {
	cache := newDecisionCacheWithTTL(100, 50*time.Millisecond)

	cache.Put("dec_ttl1", &models.DecisionResponse{DecisionID: "dec_ttl1"})
	cache.Put("dec_ttl2", &models.DecisionResponse{DecisionID: "dec_ttl2"})

	resp, ok := cache.Get("dec_ttl1")
	if !ok {
		t.Fatal("expected dec_ttl1 to be found immediately after Put")
	}
	if resp.DecisionID != "dec_ttl1" {
		t.Errorf("DecisionID = %v, want dec_ttl1", resp.DecisionID)
	}

	time.Sleep(100 * time.Millisecond)

	_, ok = cache.Get("dec_ttl1")
	if ok {
		t.Error("expected dec_ttl1 to be expired after TTL")
	}

	_, ok = cache.Get("dec_ttl2")
	if ok {
		t.Error("expected dec_ttl2 to be expired after TTL")
	}
}

func TestDecisionCache_MaxSizeEviction(t *testing.T) {
	cache := newDecisionCacheWithSize(3)

	for i := 0; i < 5; i++ {
		cache.Put("dec_max"+string(rune('0'+i)), &models.DecisionResponse{DecisionID: "dec_max" + string(rune('0'+i))})
	}

	count, _ := cache.Stats()
	if count != 3 {
		t.Errorf("expected 3 entries after max size eviction, got %d", count)
	}
}

func TestDecisionCache_Cleanup(t *testing.T) {
	cache := newDecisionCacheWithTTL(100, 30*time.Millisecond)

	cache.Put("dec_cleanup1", &models.DecisionResponse{DecisionID: "dec_cleanup1"})

	time.Sleep(50 * time.Millisecond)

	cache.Put("dec_cleanup2", &models.DecisionResponse{DecisionID: "dec_cleanup2"})

	count, _ := cache.Stats()
	if count != 2 {
		t.Errorf("expected 2 entries before cleanup, got %d", count)
	}

	cache.cleanup()

	count, _ = cache.Stats()
	if count != 1 {
		t.Errorf("expected 1 entry after cleanup (expired ones removed), got %d", count)
	}
}

func TestDecisionCache_UpdateExisting(t *testing.T) {
	cache := newDecisionCache()

	cache.Put("dec_update", &models.DecisionResponse{DecisionID: "dec_update", Decision: "allow"})
	cache.Put("dec_update", &models.DecisionResponse{DecisionID: "dec_update", Decision: "escalate"})

	count, _ := cache.Stats()
	if count != 1 {
		t.Errorf("expected 1 entry after update, got %d", count)
	}

	resp, ok := cache.Get("dec_update")
	if !ok {
		t.Fatal("expected dec_update to be found")
	}
	if resp.Decision != "escalate" {
		t.Errorf("Decision = %v, want escalate", resp.Decision)
	}
}

func TestDecisionCache_Stats(t *testing.T) {
	cache := newDecisionCacheWithSize(10)

	cache.Put("dec_stats1", &models.DecisionResponse{DecisionID: "dec_stats1"})
	cache.Put("dec_stats2", &models.DecisionResponse{DecisionID: "dec_stats2"})

	count, max := cache.Stats()
	if count != 2 {
		t.Errorf("count = %d, want 2", count)
	}
	if max != 10 {
		t.Errorf("max = %d, want 10", max)
	}
}

func TestDecisionCache_StartCleanup(t *testing.T) {
	cache := newDecisionCacheWithTTL(100, 30*time.Millisecond)

	cache.Put("dec_background1", &models.DecisionResponse{DecisionID: "dec_background1"})

	cache.StartCleanup(20 * time.Millisecond)

	time.Sleep(60 * time.Millisecond)

	_, ok := cache.Get("dec_background1")
	if ok {
		t.Error("expected dec_background1 to be cleaned up by background cleanup")
	}
}

func newDecisionCacheWithTTL(maxSize int, ttl time.Duration) *decisionCache {
	return &decisionCache{
		decisions: make(map[string]*decisionEntry),
		maxSize:   maxSize,
		ttl:       ttl,
		order:     make([]string, 0, maxSize),
	}
}

func newDecisionCacheWithSize(maxSize int) *decisionCache {
	return newDecisionCacheWithTTL(maxSize, 10*time.Minute)
}