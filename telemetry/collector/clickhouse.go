package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type ClickHouseWriter struct {
	endpoint   string
	database   string
	username   string
	password   string
	httpClient *http.Client
	mu         sync.RWMutex
	written    int64
	failed     int64
}

func NewClickHouseWriter(endpoint, database, username, password string) *ClickHouseWriter {
	return &ClickHouseWriter{
		endpoint:   strings.TrimRight(endpoint, "/"),
		database:   database,
		username:   username,
		password:   password,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

func (w *ClickHouseWriter) WriteEvents(ctx context.Context, events []*Event) error {
	if len(events) == 0 {
		return nil
	}

	var rows []string
	for _, evt := range events {
		payload, _ := json.Marshal(evt.Payload)
		rows = append(rows, fmt.Sprintf(
			"('%s','%s','1.0','%s',%d,'%s','%s','%s','%s','%s','%s','%s',now64(3))",
			escape(evt.EventID), escape(evt.EventType),
			evt.Timestamp.Format("2006-01-02 15:04:05.999"), 0,
			escape(evt.GatewayID), escape(evt.AgentID),
			"", "", "", "",
			escape(string(payload)),
		))
	}

	query := fmt.Sprintf(
		"INSERT INTO %s.events (event_id,event_type,event_version,timestamp,seq,gateway_id,agent_id,trace_id,decision_id,receipt_id,approval_id,payload) VALUES %s",
		w.database, strings.Join(rows, ","),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/?query=%s", w.endpoint, strings.ReplaceAll(query, " ", "%20")),
		nil,
	)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	if w.username != "" {
		req.Header.Set("X-ClickHouse-User", w.username)
	}
	if w.password != "" {
		req.Header.Set("X-ClickHouse-Key", w.password)
	}

	resp, err := w.httpClient.Do(req)
	if err != nil {
		atomic.AddInt64(&w.failed, int64(len(events)))
		return fmt.Errorf("clickhouse request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		atomic.AddInt64(&w.failed, int64(len(events)))
		return fmt.Errorf("clickhouse returned %d", resp.StatusCode)
	}

	atomic.AddInt64(&w.written, int64(len(events)))
	return nil
}

func (w *ClickHouseWriter) Stats() (written, failed int64) {
	return atomic.LoadInt64(&w.written), atomic.LoadInt64(&w.failed)
}

func escape(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "'", "\\'")
	return s
}
