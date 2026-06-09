package enrollment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

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
	}
}

func (s *CloudService) Enroll(organizationID string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
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
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("enrollment failed (status %d): %s", resp.StatusCode, string(respBody))
	}

	var result enrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
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
		"public_key":  fmt.Sprintf("%x", pub),
		"private_key": fmt.Sprintf("%x", priv),
	}

	if s.filePath != "" {
		data, _ := json.MarshalIndent(s.identity, "", "  ")
		_ = os.WriteFile(s.filePath, data, 0644)
	}

	return nil
}

func (s *CloudService) ConfirmEnrollment(token string) error {
	req, err := http.NewRequest(
		http.MethodPost,
		s.cloudURL+"/v1/gateways/confirm/"+s.GetIdentity().ID,
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
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("confirmation failed (status %d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func (s *CloudService) CloudHeartbeat() error {
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
}

func NewPolicySyncService(cloudURL, apiKey, gatewayID string) *PolicySyncService {
	return &PolicySyncService{
		cloudURL:   cloudURL,
		apiKey:     apiKey,
		gatewayID:  gatewayID,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

func (ps *PolicySyncService) FetchDistributions() ([]distributionItem, error) {
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
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil, fmt.Errorf("decoding distributions: %w", err)
	}

	return items, nil
}

func (ps *PolicySyncService) FetchPolicy(policyID string) (*policySyncResponse, error) {
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
	if err := json.NewDecoder(resp.Body).Decode(&item); err != nil {
		return nil, fmt.Errorf("decoding policy: %w", err)
	}

	ps.lastSyncAt = time.Now()
	return &item, nil
}

func (ps *PolicySyncService) LastSyncAt() time.Time {
	return ps.lastSyncAt
}
