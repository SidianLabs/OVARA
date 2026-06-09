package observe

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

type OTLPExporter struct {
	mu          sync.Mutex
	spans       []OTLPSpan
	maxSpans    int
	flushPeriod time.Duration
	stopCh      chan struct{}
}

type OTLPSpan struct {
	TraceID      string            `json:"traceId"`
	SpanID       string            `json:"spanId"`
	Name         string            `json:"name"`
	StartTime    time.Time         `json:"startTime"`
	EndTime      time.Time         `json:"endTime"`
	Attributes   map[string]string `json:"attributes"`
	StatusCode   string            `json:"statusCode"`
	ErrorMessage string            `json:"errorMessage,omitempty"`
}

func NewOTLPExporter(maxSpans int, flushPeriod time.Duration) *OTLPExporter {
	if maxSpans <= 0 {
		maxSpans = 1000
	}
	e := &OTLPExporter{
		maxSpans:    maxSpans,
		flushPeriod: flushPeriod,
		stopCh:      make(chan struct{}),
	}
	return e
}

func (e *OTLPExporter) StartFlushLoop() {
	go func() {
		ticker := time.NewTicker(e.flushPeriod)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				e.flush()
			case <-e.stopCh:
				e.flush()
				return
			}
		}
	}()
}

func (e *OTLPExporter) flush() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if len(e.spans) == 0 {
		return
	}

	data, err := json.Marshal(struct {
		ResourceSpans []OTLPSpan `json:"resourceSpans"`
	}{ResourceSpans: e.spans})
	if err != nil {
		fmt.Printf("OTLP flush marshal error: %v\n", err)
		return
	}

	fmt.Printf("[OTLP] flushing %d spans (%d bytes)\n", len(e.spans), len(data))
	e.spans = e.spans[:0]
}

func (e *OTLPExporter) AddSpan(span OTLPSpan) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.spans = append(e.spans, span)
	if len(e.spans) > e.maxSpans {
		e.spans = e.spans[len(e.spans)-e.maxSpans:]
	}
}

func (e *OTLPExporter) Spans() []OTLPSpan {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]OTLPSpan, len(e.spans))
	copy(out, e.spans)
	return out
}

func (e *OTLPExporter) Close() error {
	close(e.stopCh)
	return nil
}
