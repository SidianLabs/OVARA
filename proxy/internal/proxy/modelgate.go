package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// Model-provider APIs are the one write channel an agent needs without asking:
// it talks to its own model. But a model request can make the PROVIDER's
// servers contact a URL the agent chose (an MCP connector, a web fetch tool, an
// image or document given by URL), and that turns "talk to my model" into "send
// this data anywhere" with the user's key attached. The model gate reads the
// JSON body of every allowed POST to a model host and refuses those features.
// It runs whatever policy.json says, so older policies are covered too.

// defaultModelHosts are the hosts whose request bodies are checked.
var defaultModelHosts = []string{"api.anthropic.com", "api.openai.com"}

// maxModelBody bounds how much of a model request is read to check it. A
// request larger than this is refused rather than forwarded unchecked.
const maxModelBody = 32 << 20

// SetModelGate turns the model-API body check on or off (default on) and sets
// the hosts it applies to (nil keeps the defaults).
func (s *Server) SetModelGate(on bool, hosts []string) {
	s.modelGateOff = !on
	if hosts != nil {
		s.modelHosts = hosts
	}
}

func (s *Server) isModelHost(host string) bool {
	hosts := s.modelHosts
	if hosts == nil {
		hosts = defaultModelHosts
	}
	return matchHostGlob(hosts, host)
}

// actionModelFeature is the question asked when a model request uses one of
// those features: the gate no longer refuses outright, a person decides
// (resource "model:<host> <reason>"). SetModelGateAsk(false) restores the
// flat refusal.
const actionModelFeature = "model.server_feature"

// SetModelGateAsk chooses whether a model-gate finding is a question for a
// person (default) or a flat refusal.
func (s *Server) SetModelGateAsk(on bool) { s.modelGateNoAsk = !on }

// modelAskable reports whether a model-gate finding may be put to a person.
// Only findings about what the request asks the provider to do qualify; a
// body the gate could not read is refused, since the person could not read
// it either.
func modelAskable(why string) bool {
	switch why {
	case "model_request_mcp_connector", "model_request_remote_url", "model_request_server_tool", "model_request_not_json":
		return true
	}
	return false
}

// modelRequestRefusal returns why a request to a model host must not be
// forwarded without a further answer, or "". hb is its held body.
func (s *Server) modelRequestRefusal(r *http.Request, hb *heldBody) string {
	if s.modelGateOff || !s.isModelHost(r.URL.Hostname()) {
		return ""
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return ""
	}
	if hb == nil {
		return ""
	}
	if ce := r.Header.Values("Content-Encoding"); len(ce) > 0 {
		for _, v := range ce {
			if !strings.EqualFold(strings.TrimSpace(v), "identity") {
				return "model_request_encoded"
			}
		}
	}
	if hb.size > maxModelBody {
		return "model_request_too_large"
	}
	body, err := io.ReadAll(hb.reader())
	if err != nil {
		return "model_request_unreadable"
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return ""
	}
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if ct != "" && !strings.Contains(ct, "json") {
		// Multipart uploads (files, audio) and anything else that is not a
		// JSON model call: not something the agent needs to do unasked.
		return "model_request_not_json"
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return "model_request_not_json"
	}
	if why := modelValueRefusal(v); why != "" {
		return why
	}
	return ""
}

// serverToolPrefixes are tool "type" values that make the provider reach the
// network on the agent's behalf. Client-side tools (bash, text editor,
// computer use, the agent's own functions) are not listed: the agent runs
// those itself, through Ovara.
var serverToolPrefixes = []string{
	"web_fetch", "web_search", // Anthropic server tools; OpenAI web_search(_preview)
	"mcp", "connector", "file_search", // OpenAI Responses hosted tools
}

// skipKeys hold data that is not an instruction to the provider: tool inputs
// the agent already ran, and JSON Schemas describing its own tools. A URL in
// a past tool call is history, not a fetch.
var skipKeys = map[string]bool{"arguments": true, "input_schema": true, "parameters": true, "schema": true}

// modelValueRefusal walks the decoded JSON and reports the first feature that
// makes the provider fetch or connect on the agent's behalf.
func modelValueRefusal(v any) string {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			lk := strings.ToLower(k)
			if skipKeys[lk] {
				continue
			}
			// A tool call's "input" is what the agent already ran. (OpenAI's
			// top-level "input" is the prompt, and is checked.)
			if lk == "input" {
				if typ, _ := t["type"].(string); typ == "tool_use" {
					continue
				}
			}
			switch lk {
			case "mcp_servers", "server_url", "connector_id":
				if !isEmptyJSON(val) {
					return "model_request_mcp_connector"
				}
			case "image_url", "file_url", "document_url", "audio_url":
				if s := jsonURL(val); s != "" && !strings.HasPrefix(strings.ToLower(s), "data:") {
					return "model_request_remote_url"
				}
			case "type":
				if s, ok := val.(string); ok {
					ls := strings.ToLower(s)
					if ls == "url" { // Anthropic {"source": {"type": "url", "url": ...}}
						return "model_request_remote_url"
					}
					for _, p := range serverToolPrefixes {
						if ls == p || strings.HasPrefix(ls, p+"_") {
							return "model_request_server_tool"
						}
					}
				}
			}
			if why := modelValueRefusal(val); why != "" {
				return why
			}
		}
	case []any:
		for _, e := range t {
			if why := modelValueRefusal(e); why != "" {
				return why
			}
		}
	}
	return ""
}

// jsonURL returns the URL a field holds, whether it is a string or an object
// like {"url": "..."}.
func jsonURL(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case map[string]any:
		if s, ok := t["url"].(string); ok {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func isEmptyJSON(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return t == ""
	case []any:
		return len(t) == 0
	case map[string]any:
		return len(t) == 0
	case bool:
		return !t
	}
	return false
}

// credentialHeaders are request headers that carry a credential. On a host
// Ovara holds a key for, the agent's own values are removed before the real
// one is attached: otherwise an agent could add a second credential (an
// attacker's account) that the upstream honours instead of, or as well as,
// the injected one.
var credentialHeaders = []string{
	"Authorization", "X-Api-Key", "Api-Key", "X-Auth-Token", "X-Goog-Api-Key",
	"Private-Token", "Job-Token", "X-Access-Token", "X-Token", "Cookie",
}

func stripCredentialHeaders(h http.Header) {
	for _, k := range credentialHeaders {
		h.Del(k)
	}
	for k := range h {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "api-key") || strings.Contains(lk, "apikey") || strings.Contains(lk, "token") || strings.Contains(lk, "secret") {
			h.Del(k)
		}
	}
}
