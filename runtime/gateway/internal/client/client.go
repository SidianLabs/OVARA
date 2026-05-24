package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"ovara.runtime.gateway/internal/models"
)

type GatewayClient struct {
	baseURL    string
	httpClient *http.Client
	agentID    string
}

func NewGatewayClient(baseURL, agentID string) *GatewayClient {
	return &GatewayClient{
		baseURL: baseURL,
		agentID: agentID,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

type CheckOption func(*models.ActionRequest)

func WithIdentity(identity *models.AgentIdentity) CheckOption {
	return func(req *models.ActionRequest) {
		req.AgentIdentity = identity
	}
}

func WithLease(lease *models.CapabilityLease) CheckOption {
	return func(req *models.ActionRequest) {
		req.CapabilityLease = lease
	}
}

func WithMetadata(metadata map[string]any) CheckOption {
	return func(req *models.ActionRequest) {
		if data, err := json.Marshal(metadata); err == nil {
			req.Metadata = data
		}
	}
}

func (c *GatewayClient) Check(actionType models.ActionType, resource string, environment models.Environment, opts ...CheckOption) (*models.DecisionResponse, error) {
	req := models.ActionRequest{
		ActionType:  actionType,
		Resource:    resource,
		Environment: environment,
	}

	for _, opt := range opts {
		opt(&req)
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	resp, err := c.httpClient.Post(c.baseURL+"/v1/runtime/check", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("calling gateway: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gateway returned status %d", resp.StatusCode)
	}

	var decision models.DecisionResponse
	if err := json.NewDecoder(resp.Body).Decode(&decision); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &decision, nil
}

func (c *GatewayClient) Allow(actionType models.ActionType, resource string, environment models.Environment, opts ...CheckOption) (bool, error) {
	resp, err := c.Check(actionType, resource, environment, opts...)
	if err != nil {
		return false, err
	}
	return resp.Decision == models.DecisionAllow, nil
}