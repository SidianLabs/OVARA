package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"ovara.proxy/internal/gateway"
)

// capturingGateway answers every check with "allow" and records the metadata
// the proxy sent.
func capturingGateway(t *testing.T, meta *string) *gateway.Client {
	t.Helper()
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/runtime/check" {
			b, _ := io.ReadAll(r.Body)
			var m map[string]json.RawMessage
			if json.Unmarshal(b, &m) == nil {
				*meta = string(m["metadata"])
			}
		}
		json.NewEncoder(w).Encode(map[string]string{"decision": "allow", "decision_id": "d"})
	}))
	t.Cleanup(gw.Close)
	return gateway.New(gw.URL, "", "test")
}
