package enrollment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"ovara.runtime.gateway/internal/persist"
)

// maxCloudResponseBytes bounds control-plane response bodies.
const maxCloudResponseBytes = 10 << 20 // 10 MiB

// checkCloudURL enforces https for control-plane endpoints so Bearer API keys
// are never sent over cleartext. Plain http is permitted only for loopback
// targets (localhost / 127.0.0.1 / ::1), e.g. local dev and tests.
func checkCloudURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("invalid control plane URL: %q", rawURL)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil
		}
		return fmt.Errorf("control plane URL must use https (got http://%s); refusing to send credentials over cleartext", u.Host)
	}
	return fmt.Errorf("unsupported control plane URL scheme %q (https required)", u.Scheme)
}

type CloudConfig struct {
	ControlPlaneURL     string `json:"control_plane_url"`
	ControlPlaneAPIKey  string `json:"control_plane_api_key"`
	PolicySource        string `json:"policy_source"`
}

type CloudService struct {
	*localService
	cloudURL      string
	apiKey        string
	httpClient    *http.Client
	policySyncer  *PolicySyncService
	urlErr        error
}

type enrollRequest struct {
	OrganizationID string `json:"organizationId"`
	Name           string `json:"name"`
	Environment    string `json:"environment"`
	Region         string `json:"region"`
	PublicKey      string `json:"publicKey"`
}

type enrollResponse struct {
	ID               string    `json:"id"`
	Status           string    `json:"status"`
	EnrollmentToken  string    `json:"enrollmentToken"`
	EnrollmentExpiresAt *time.Time `json:"enrollmentExpiresAt"`
}

type heartbeatRequest struct {
	PolicyVersion string `json:"policy_version"`
}

type policySyncResponse struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Version     int             `json:"version"`
	Rules       json.RawMessage `json:"rules"`
	PublishedAt time.Time       `json:"publishedAt"`
}

type distributionItem struct {
	ID        string `json:"id"`
	PolicyID  string `json:"policyId"`
	GatewayID string `json:"gatewayId"`
	Status    string `json:"status"`
}

func NewCloudService(filePath string, cloudCfg CloudConfig, opts ...func(*localService)) *CloudService {
	return &CloudService{
		localService: NewLocalService(filePath, opts...),
		cloudURL:     cloudCfg.ControlPlaneURL,
		apiKey:       cloudCfg.ControlPlaneAPIKey,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		urlErr: checkCloudURL(cloudCfg.ControlPlaneURL),
	}
}

func (s *CloudService) Enroll(organizationID string) error {
	if s.urlErr != nil {
		return s.urlErr
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generating key pair: %w", err)
	}

	body := enrollRequest{
		OrganizationID: organizationID,
		Name:           s.defaultName,
		Environment:    "production",
		Region:         "us-east-1",
		PublicKey:      fmt.Sprintf("%x", pub),
	}

	reqBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshaling enroll request: %w", err)
	}

	req, err := http.NewRequest(
		http.MethodPost,
		s.cloudURL+"/v1/gateways/enroll",
		bytes.NewReader(reqBody),
	)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.apiKey)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("enrolling with control plane: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxCloudResponseBytes))
		if err != nil {
			return fmt.Errorf("enrollment failed (status %d): failed to read response body: %w", resp.StatusCode, err)
		}
		return fmt.Errorf("enrollment failed (status %d): %s", resp.StatusCode, string(respBody))
	}

	var result enrollResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxCloudResponseBytes)).Decode(&result); err != nil {
		return fmt.Errorf("decoding enrollment response: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.identity == nil {
		s.identity = &GatewayIdentity{}
	}
	s.identity.ID = result.ID
	s.identity.EnrollmentState = EnrollmentStateEnrolled
	s.identity.RegisteredAt = time.Now().UTC()
	s.identity.LastSeenAt = time.Now().UTC()
	s.identity.Tags = map[string]string{
		"public_key": fmt.Sprintf("%x", pub),
	}

	if s.filePath != "" {
		data, err := json.MarshalIndent(s.identity, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling identity: %w", err)
		}
		if err := persist.WriteFileAtomic(s.filePath, data, 0600); err != nil {
			return fmt.Errorf("persisting identity: %w", err)
		}
	}

	return nil
}

func (s *CloudService) ConfirmEnrollment(token string) error {
	if s.urlErr != nil {
		return s.urlErr
	}
	identity := s.GetIdentity()
	if identity == nil {
		return fmt.Errorf("gateway not initialized")
	}
	req, err := http.NewRequest(
		http.MethodPost,
		s.cloudURL+"/v1/gateways/confirm/"+identity.ID,
		nil,
	)
	if err != nil {
		return fmt.Errorf("creating confirm request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.apiKey)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("confirming enrollment: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxCloudResponseBytes))
		return fmt.Errorf("confirmation failed (status %d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func (s *CloudService) CloudHeartbeat() error {
	if s.urlErr != nil {
		return s.urlErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.identity == nil {
		return fmt.Errorf("gateway not initialized")
	}

	body := heartbeatRequest{
		PolicyVersion: "v1",
	}

	reqBody, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(
		http.MethodPost,
		s.cloudURL+"/v1/gateways/"+s.identity.ID+"/heartbeat",
		bytes.NewReader(reqBody),
	)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.apiKey)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending heartbeat: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("heartbeat failed (status %d)", resp.StatusCode)
	}

	s.identity.LastSeenAt = time.Now().UTC()
	return nil
}

type PolicySyncService struct {
	cloudURL    string
	apiKey      string
	gatewayID   string
	httpClient  *http.Client
	lastSyncAt  time.Time
	urlErr      error
}

func NewPolicySyncService(cloudURL, apiKey, gatewayID string) *PolicySyncService {
	return &PolicySyncService{
		cloudURL:   cloudURL,
		apiKey:     apiKey,
		gatewayID:  gatewayID,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		urlErr:     checkCloudURL(cloudURL),
	}
}

func (ps *PolicySyncService) FetchDistributions() ([]distributionItem, error) {
	if ps.urlErr != nil {
		return nil, ps.urlErr
	}
	req, err := http.NewRequest(
		http.MethodGet,
		ps.cloudURL+"/v1/policies/distributions/"+ps.gatewayID,
		nil,
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+ps.apiKey)

	resp, err := ps.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching distributions: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("distributions fetch failed (status %d)", resp.StatusCode)
	}

	var items []distributionItem
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxCloudResponseBytes)).Decode(&items); err != nil {
		return nil, fmt.Errorf("decoding distributions: %w", err)
	}

	return items, nil
}

func (ps *PolicySyncService) FetchPolicy(policyID string) (*policySyncResponse, error) {
	if ps.urlErr != nil {
		return nil, ps.urlErr
	}
	req, err := http.NewRequest(
		http.MethodGet,
		ps.cloudURL+"/v1/policies/"+policyID,
		nil,
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+ps.apiKey)

	resp, err := ps.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching policy: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("policy fetch failed (status %d)", resp.StatusCode)
	}

	var item policySyncResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxCloudResponseBytes)).Decode(&item); err != nil {
		return nil, fmt.Errorf("decoding policy: %w", err)
	}

	ps.lastSyncAt = time.Now()
	return &item, nil
}

func (ps *PolicySyncService) LastSyncAt() time.Time {
	return ps.lastSyncAt
}
