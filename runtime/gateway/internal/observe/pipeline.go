package observe

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"ovara.runtime.gateway/internal/events"
)

type Exporter interface {
	Export(ctx context.Context, evt *events.Event) error
	Close() error
}

type TelemetryPipeline struct {
	exporters []Exporter
	mu        sync.RWMutex
	running   bool
}

func NewPipeline(exporters ...Exporter) *TelemetryPipeline {
	return &TelemetryPipeline{
		exporters: exporters,
	}
}

func (p *TelemetryPipeline) Start(ctx context.Context) {
	p.mu.Lock()
	p.running = true
	p.mu.Unlock()
}

func (p *TelemetryPipeline) Send(ctx context.Context, evt *events.Event) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if !p.running {
		return
	}
	for _, exp := range p.exporters {
		_ = exp.Export(ctx, evt)
	}
}

func (p *TelemetryPipeline) SendSync(evt *events.Event) []error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var errs []error
	for _, exp := range p.exporters {
		if err := exp.Export(context.Background(), evt); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

func (p *TelemetryPipeline) Shutdown() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.running = false
	for _, exp := range p.exporters {
		_ = exp.Close()
	}
}

type ConsoleExporter struct {
	encoder *json.Encoder
	mu      sync.Mutex
}

func NewConsoleExporter() *ConsoleExporter {
	return &ConsoleExporter{}
}

func (c *ConsoleExporter) Export(_ context.Context, evt *events.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	data, err := json.Marshal(evt)
	if err != nil {
		return err
	}
	_, _ = json.Marshal(struct {
		Timestamp time.Time `json:"@timestamp"`
		Event     string    `json:"@event"`
	}{Timestamp: evt.Timestamp, Event: string(data)})
	return nil
}

func (c *ConsoleExporter) Close() error { return nil }

type NoopExporter struct{}

func (n *NoopExporter) Export(_ context.Context, _ *events.Event) error { return nil }
func (n *NoopExporter) Close() error                                   { return nil }
