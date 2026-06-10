package observe

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

type TracerConfig struct {
	ServiceName string
	Endpoint    string
	SampleRate  float64
}

func DefaultTracerConfig() TracerConfig {
	return TracerConfig{
		ServiceName: "ovara-gateway",
		Endpoint:    "localhost:4317",
		SampleRate:  1.0,
	}
}

type TracerProvider struct {
	config   TracerConfig
	mu       sync.Mutex
	exporter *otlpHTTPExporter
	running  bool
}

type otlpHTTPExporter struct {
	endpoint string
	client   *http.Client
	mu       sync.Mutex
	spans    []OTLPSpan
	batch    int
}

func newOTLPHTTPExporter(endpoint string) *otlpHTTPExporter {
	return &otlpHTTPExporter{
		endpoint: endpoint,
		client:   &http.Client{Timeout: 10 * time.Second},
		batch:    100,
	}
}

func (e *otlpHTTPExporter) exportSpans(spans []OTLPSpan) {
	if len(spans) == 0 {
		return
	}

	payload := map[string]any{
		"resourceSpans": []map[string]any{
			{
				"resource": map[string]any{
					"attributes": []map[string]any{
						{"key": "service.name", "value": map[string]any{"stringValue": "ovara-gateway"}},
					},
				},
				"scopeSpans": []map[string]any{
					{
						"spans": spans,
					},
				},
			},
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return
	}

	url := fmt.Sprintf("http://%s/v1/traces", e.endpoint)
	req, err := http.NewRequest("POST", url, io.NopCloser(bytesReader(data)))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, _ := e.client.Do(req)
	if resp != nil {
		resp.Body.Close()
	}
}

func bytesReader(b []byte) io.Reader {
	return &sliceReader{data: b}
}

type sliceReader struct {
	data []byte
	off  int
}

func (r *sliceReader) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.off:])
	r.off += n
	return n, nil
}

type noopTracerProvider struct{}

func (n *noopTracerProvider) Shutdown(_ context.Context) error { return nil }

func generateTraceID() string {
	var buf [16]byte
	_, _ = rand.Read(buf[:])
	return hex.EncodeToString(buf[:])
}

func generateSpanID() string {
	var buf [8]byte
	_, _ = rand.Read(buf[:])
	return hex.EncodeToString(buf[:])
}

func InitTracer(config TracerConfig) *TracerProvider {
	if config.Endpoint == "" {
		config.Endpoint = "localhost:4317"
	}
	if config.SampleRate <= 0 {
		config.SampleRate = 1.0
	}
	if config.ServiceName == "" {
		config.ServiceName = "ovara-gateway"
	}

	exporter := newOTLPHTTPExporter(config.Endpoint)

	tp := &TracerProvider{
		config:   config,
		exporter: exporter,
		running:  true,
	}

	return tp
}

func (tp *TracerProvider) Shutdown(ctx context.Context) error {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	tp.running = false
	return nil
}

func (tp *TracerProvider) IsRunning() bool {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	return tp.running
}

func (tp *TracerProvider) Config() TracerConfig {
	return tp.config
}
