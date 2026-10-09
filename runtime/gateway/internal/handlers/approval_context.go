package handlers

import "encoding/json"

// Limits on what a request may place in front of a human approver. The
// context is display-only, so it is bounded hard: a request cannot use it to
// flood the approval screen or the journal.
const (
	maxContextEntries  = 12
	maxContextKeyLen   = 40
	maxContextValueLen = 600
)

// approvalContextFromMetadata extracts {"proxy_context": {"k": "v", ...}} from
// the metadata of the request the gateway evaluated. Anything that is not a
// flat object of short strings is dropped.
func approvalContextFromMetadata(meta json.RawMessage) map[string]string {
	if len(meta) == 0 {
		return nil
	}
	var outer struct {
		ProxyContext map[string]any `json:"proxy_context"`
	}
	if json.Unmarshal(meta, &outer) != nil || len(outer.ProxyContext) == 0 {
		return nil
	}
	out := make(map[string]string, len(outer.ProxyContext))
	for k, v := range outer.ProxyContext {
		s, ok := v.(string)
		if !ok || k == "" || len(out) >= maxContextEntries {
			continue
		}
		if len(k) > maxContextKeyLen {
			k = k[:maxContextKeyLen]
		}
		if len(s) > maxContextValueLen {
			s = s[:maxContextValueLen] + "…"
		}
		out[k] = s
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
