package collector

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

type Writer interface {
	WriteEvents(ctx context.Context, events []*Event) error
}

type Pipeline struct {
	mu        sync.Mutex
	buffer    []*Event
	bufSize   int
	writers   []Writer
	collector *NATSCollector
	flushCh   chan struct{}
	stopCh    chan struct{}
	doneCh    chan struct{}
	running   int32
}

func NewPipeline(nc *NATSCollector, writers []Writer, bufSize int) *Pipeline {
	if bufSize <= 0 {
		bufSize = 1024
	}
	return &Pipeline{
		collector: nc,
		writers:   writers,
		buffer:    make([]*Event, 0, bufSize),
		bufSize:   bufSize,
		flushCh:   make(chan struct{}, 1),
		stopCh:    make(chan struct{}),
		doneCh:    make(chan struct{}),
	}
}

func (p *Pipeline) Ingest(evt *Event) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = p.collector.Publish(ctx, evt)
	}()

	p.mu.Lock()
	p.buffer = append(p.buffer, evt)
	shouldFlush := len(p.buffer) >= p.bufSize
	p.mu.Unlock()

	if shouldFlush {
		select {
		case p.flushCh <- struct{}{}:
		default:
		}
	}
}

func (p *Pipeline) Start(flushInterval time.Duration) {
	atomic.StoreInt32(&p.running, 1)

	go func() {
		defer close(p.doneCh)
		ticker := time.NewTicker(flushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				p.flush()
			case <-p.flushCh:
				p.flush()
			case <-p.stopCh:
				p.flush()
				return
			}
		}
	}()
}

func (p *Pipeline) flush() {
	p.mu.Lock()
	if len(p.buffer) == 0 {
		p.mu.Unlock()
		return
	}
	batch := make([]*Event, len(p.buffer))
	copy(batch, p.buffer)
	p.buffer = p.buffer[:0]
	p.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, w := range p.writers {
		_ = w.WriteEvents(ctx, batch)
	}
}

func (p *Pipeline) Stop() {
	close(p.stopCh)
	<-p.doneCh
	atomic.StoreInt32(&p.running, 0)
}

func (p *Pipeline) IsRunning() bool {
	return atomic.LoadInt32(&p.running) == 1
}
