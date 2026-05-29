package execution

import (
	"log"
	"sync"
	"time"
)

type Sweeper struct {
	store       Store
	intervalSec int
	mu          sync.Mutex
	stopMu      sync.Mutex
	stopChan    chan struct{}
	running     bool
}

func NewSweeper(store Store) *Sweeper {
	return &Sweeper{
		store:    store,
		intervalSec: 300,
		stopChan: make(chan struct{}),
	}
}

func (s *Sweeper) SetInterval(sec int) {
	if sec > 0 {
		s.intervalSec = sec
	}
}

func (s *Sweeper) Start(intervalSec int) {
	if intervalSec > 0 {
		s.intervalSec = intervalSec
	}
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.mu.Unlock()

	ticker := time.NewTicker(time.Duration(s.intervalSec) * time.Second)
	go func() {
		for {
			s.mu.Lock()
			if !s.running {
				s.mu.Unlock()
				ticker.Stop()
				return
			}
			s.mu.Unlock()
			select {
			case <-ticker.C:
				s.Sweep()
			case <-s.stopChan:
			}
		}
	}()
}

func (s *Sweeper) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	s.mu.Unlock()
	close(s.stopChan)
}

func (s *Sweeper) Sweep() (removed int, err error) {
	if fb, ok := s.store.(*FileBackedStore); ok {
		removed, err = fb.Sweep()
		if err != nil {
			log.Printf("SWEEP execution error=%v", err)
			return 0, err
		}
		if removed > 0 {
			log.Printf("SWEEP execution removed=%d", removed)
		}
		return removed, nil
	}
	return 0, nil
}

func (s *Sweeper) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}