package enrollment

import (
	"crypto/rand"
	"encoding/json"
	"encoding/binary"
	"fmt"
	"os"
	"sync"
	"time"

	"ovara.runtime.gateway/internal/metrics"
)

type Service interface {
	GetIdentity() *GatewayIdentity
	GetStatus() *EnrollmentStatus
	Initialize(env string) error
	Heartbeat() error
	IsEnrolled() bool
	StartHeartbeat(interval time.Duration) func()
}

type localService struct {
	mu            sync.RWMutex
	identity      *GatewayIdentity
	filePath      string
	stopCh        chan struct{}
	defaultName   string
	defaultVersion string
}

func NewLocalService(filePath string, opts ...func(*localService)) *localService {
	svc := &localService{
		filePath: filePath,
	}
	for _, opt := range opts {
		opt(svc)
	}
	return svc
}

func WithGatewayName(name string) func(*localService) {
	return func(s *localService) {
		s.defaultName = name
	}
}

func WithGatewayVersion(version string) func(*localService) {
	return func(s *localService) {
		s.defaultVersion = version
	}
}

func (s *localService) GetIdentity() *GatewayIdentity {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.identity == nil {
		return nil
	}
	out := *s.identity
	return &out
}

func (s *localService) GetStatus() *EnrollmentStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.identity == nil {
		return nil
	}
	return &EnrollmentStatus{
		GatewayID:        s.identity.ID,
		EnrollmentState:  s.identity.EnrollmentState,
		Environment:      s.identity.Environment,
		RegisteredAt:     s.identity.RegisteredAt,
		LastSeenAt:       s.identity.LastSeenAt,
		IsHealthy:        true,
	}
}

func (s *localService) Initialize(env string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()

	if s.identity == nil {
		if s.filePath != "" {
			if data, err := os.ReadFile(s.filePath); err == nil {
				var stored GatewayIdentity
				if json.Unmarshal(data, &stored) == nil {
					stored.LastSeenAt = now
					s.identity = &stored
					return nil
				}
			}
		}

		name := s.defaultName
		if name == "" {
			name = "local-gateway"
		}
		version := s.defaultVersion
		if version == "" {
			version = "0.9.0"
		}
		s.identity = &GatewayIdentity{
			ID:              newGatewayID(),
			Name:            name,
			Version:         version,
			Environment:     env,
			RegisteredAt:    now,
			LastSeenAt:      now,
			EnrollmentState: EnrollmentStateLocal,
			Tags:            make(map[string]string),
		}
	} else {
		s.identity.LastSeenAt = now
	}

	if s.filePath != "" {
		if err := os.MkdirAll(s.dir(), 0755); err != nil {
			return err
		}
		data, err := json.MarshalIndent(s.identity, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(s.filePath, data, 0644)
	}

	return nil
}

func (s *localService) Heartbeat() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.identity == nil {
		return fmt.Errorf("gateway not initialized")
	}

	s.identity.LastSeenAt = time.Now().UTC()

	if s.filePath != "" {
		data, err := json.MarshalIndent(s.identity, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(s.filePath, data, 0644); err != nil {
			return err
		}
	}

	metrics.RecordHeartbeat()
	return nil
}

func (s *localService) IsEnrolled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.identity == nil {
		return false
	}
	return s.identity.EnrollmentState == EnrollmentStateEnrolled
}

func (s *localService) StartHeartbeat(interval time.Duration) func() {
	var stopOnce sync.Once
	s.mu.Lock()
	s.stopCh = make(chan struct{})
	s.mu.Unlock()

	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				s.Heartbeat()
			case <-s.stopCh:
				ticker.Stop()
				return
			}
		}
	}()

	return func() {
		stopOnce.Do(func() {
			s.mu.Lock()
			close(s.stopCh)
			s.mu.Unlock()
		})
	}
}

func (s *localService) dir() string {
	if s.filePath == "" {
		return ""
	}
	for i := len(s.filePath) - 1; i >= 0; i-- {
		if s.filePath[i] == '/' {
			return s.filePath[:i]
		}
	}
	return ""
}

func newGatewayID() string {
	var b [8]byte
	rand.Read(b[:])
	nanos := time.Now().UnixNano()
	return fmt.Sprintf("gw_%d%06d", nanos/1000000, nanos%1000000) + fmt.Sprintf("%04x", binary.BigEndian.Uint32(b[:4]))
}