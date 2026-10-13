package proxy

import (
	"ovara.proxy/internal/config"
)

// limits are the size bounds a deployment may tune (config.go). Zero values
// never reach the Server: defaults fill them.
type limits struct {
	maxHeldBody    int64 // bodies held for review, then sent byte for byte
	maxPush        int64 // git push bodies
	maxUploadPack  int64 // git fetch negotiation bodies
	maxReadRequest int   // path + query + extra headers of a GET/HEAD
}

func defaultLimits() limits {
	return limits{
		maxHeldBody:    defaultMaxHeldBody,
		maxPush:        defaultMaxPushBytes,
		maxUploadPack:  defaultMaxUploadPack,
		maxReadRequest: defaultMaxReadRequest,
	}
}

// ApplyConfig sets the request size limits, the per-host egress budget and
// the model-gate question switch from the config file. Absent or zero fields
// keep the defaults.
func (s *Server) ApplyConfig(c *config.Config) {
	if c.MaxHeldBodyBytes > 0 {
		s.limits.maxHeldBody = c.MaxHeldBodyBytes
	}
	if c.MaxPushBytes > 0 {
		s.limits.maxPush = c.MaxPushBytes
	}
	if c.MaxUploadPackBytes > 0 {
		s.limits.maxUploadPack = c.MaxUploadPackBytes
	}
	if c.MaxReadRequestBytes > 0 {
		s.limits.maxReadRequest = c.MaxReadRequestBytes
	}
	if b := c.EgressBudget; b != nil {
		s.SetEgressBudget(!b.Off, b.RequestsPerMinute, b.BytesPerMinute)
	}
	if c.ModelGateAsk != nil {
		s.modelGateNoAsk = !*c.ModelGateAsk
	}
}
