package execution

import (
	"sync"
	"time"
)

type Sweeper struct {
	store      Store
	intervalSec int
	mu         sync.Mutex
	stopChan   chan struct{}
	running    bool
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
			select {
			case <-ticker.C:
				s.Sweep()
			case <-s.stopChan:
				ticker.Stop()
				s.mu.Lock()
				s.running = false
				s.mu.Unlock()
				return
			}
		}
	}()
}

func (s *Sweeper) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return
	}
	close(s.stopChan)
	s.running = false
	s.stopChan = make(chan struct{})
}

func (s *Sweeper) Sweep() (removed int, err error) {
	if fb, ok := s.store.(*FileBackedStore); ok {
		return fb.Sweep()
	}
	return 0, nil
}

func (s *Sweeper) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}