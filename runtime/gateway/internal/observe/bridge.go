package observe

import (
	"context"
	"time"

	"ovara.runtime.gateway/internal/events"
)

type MetricsSnapshotter interface {
	Snapshot() MetricsSnapshot
}

type MetricsSnapshot struct {
	TotalDecisions     int
	AvgLatencyMs       int64
	LastLatencyMs      int64
	ApprovalCounts     int
	HeartbeatCount     int
	PolicyReloadStatus string
	PolicyReloadLastAt time.Time
	PolicyReloadErrMsg string
}

type MetricsBridge struct {
	metrics    MetricsSnapshotter
	pipeline   *TelemetryPipeline
	gatewayID  string
	interval   time.Duration
	stopCh     chan struct{}
}

func NewMetricsBridge(m MetricsSnapshotter, p *TelemetryPipeline, gatewayID string, interval time.Duration) *MetricsBridge {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &MetricsBridge{
		metrics:   m,
		pipeline:  p,
		gatewayID: gatewayID,
		interval:  interval,
		stopCh:    make(chan struct{}),
	}
}

func (b *MetricsBridge) Start() {
	go func() {
		ticker := time.NewTicker(b.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				b.emitSnapshot()
			case <-b.stopCh:
				return
			}
		}
	}()
}

func (b *MetricsBridge) Stop() {
	close(b.stopCh)
}

func (b *MetricsBridge) emitSnapshot() {
	snap := b.metrics.Snapshot()

	evt := events.NewEvent("telemetry.metrics_snapshot").
		WithGatewayID(b.gatewayID).
		WithPayload(map[string]any{
			"total_decisions":     snap.TotalDecisions,
			"avg_latency_ms":      snap.AvgLatencyMs,
			"last_latency_ms":     snap.LastLatencyMs,
			"approval_count":      snap.ApprovalCounts,
			"heartbeat_count":     snap.HeartbeatCount,
			"policy_reload_status": snap.PolicyReloadStatus,
		})

	b.pipeline.Send(context.Background(), evt)
}
