package logging

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"ovara.runtime.gateway/internal/models"
)

type DecisionLogger struct {
	mu      sync.Mutex
	logFile *os.File
}

type DecisionLogEntry struct {
	Timestamp   time.Time           `json:"timestamp"`
	Request     *models.ActionRequest `json:"request"`
	Response    *models.DecisionResponse `json:"response"`
}

func NewDecisionLogger(logFile string) (*DecisionLogger, error) {
	dir := filepath.Dir(logFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("creating log dir: %w", err)
	}
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("opening log file: %w", err)
	}
	return &DecisionLogger{logFile: f}, nil
}

func (l *DecisionLogger) Log(req *models.ActionRequest, resp *models.DecisionResponse) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry := DecisionLogEntry{
		Timestamp: time.Now().UTC(),
		Request:   req,
		Response:  resp,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	_, err = l.logFile.Write(append(data, '\n'))
	return err
}

func (l *DecisionLogger) Close() error {
	if l.logFile != nil {
		return l.logFile.Close()
	}
	return nil
}