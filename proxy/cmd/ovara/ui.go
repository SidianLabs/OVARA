package main

// The local approval page: `ovara run` serves it on 127.0.0.1 so a person
// can approve or deny paused requests and see recent activity in a
// browser instead of a terminal.
//
// Security:
//   - loopback only, and the Host header must be loopback (blocks DNS
//     rebinding: a hostile website cannot make the browser talk to it);
//   - every /api call needs the page token in the Authorization header.
//     Browsers never attach that header cross-site on their own, so other
//     sites cannot forge an approval (no cookies, no CSRF);
//   - the page token is NOT the operator token: it is random per `ovara run`,
//     lives only in memory, and opens nothing but this page's endpoints. The
//     server talks to the gateway with the operator token itself, so a
//     leaked link (terminal scrollback, a log file) cannot reach the
//     gateway's admin API and stops working when `ovara run` exits;
//   - the token reaches the page in the URL fragment (#t=...), which
//     browsers never send to any server.

import (
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"strings"
)

//go:embed ui/index.html
var uiPage []byte

type uiServer struct {
	admin        *adminClient
	pageToken    string // what the browser presents; never the operator token
	receiptsFile string
	pubFile      string
}

func (u *uiServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Write(uiPage)
	})
	mux.HandleFunc("GET /api/pending", u.auth(func(w http.ResponseWriter, r *http.Request) {
		list, err := u.admin.pending()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		type item struct {
			ID        string   `json:"id"`
			What      string   `json:"what"`
			Raw       string   `json:"raw"`
			Agent     string   `json:"agent"`
			CreatedAt string   `json:"created_at"`
			Details   []string `json:"details"`
			// TrustHost is set when the request is a read from a named https
			// host, i.e. when "approve and trust this host for reads" applies.
			TrustHost string `json:"trust_host,omitempty"`
		}
		out := []item{}
		for _, a := range list {
			if u.admin.stale(a) {
				continue
			}
			th, _ := trustableHost(a.Resource)
			out = append(out, item{a.ApprovalID, describe(a.Resource), a.Resource, a.AgentID, a.CreatedAt.Format("2006-01-02T15:04:05Z07:00"), contextLines(a), th})
		}
		writeJSONResp(w, out)
	}))
	resolve := func(approve bool) http.HandlerFunc {
		return u.auth(func(w http.ResponseWriter, r *http.Request) {
			reason := ""
			if !approve {
				reason = "denied from the ovara approval page"
			}
			id := r.PathValue("id")
			// "Approve and trust this host for reads": look the request up
			// first so the host comes from the gateway's record, never from
			// anything the browser sends.
			trustHost := ""
			if approve && r.URL.Query().Get("trust") == "1" {
				list, err := u.admin.pending()
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadGateway)
					return
				}
				for _, a := range list {
					if a.ApprovalID == id {
						trustHost, _ = trustableHost(a.Resource)
					}
				}
				if trustHost == "" {
					http.Error(w, "trusting a host only applies to reads (GET/HEAD) from a named https host", http.StatusBadRequest)
					return
				}
			}
			if err := u.admin.resolve(id, approve, whoAmI()+" (browser)", reason); err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			if trustHost != "" {
				if _, err := trustReadHost(u.admin.dir, trustHost); err != nil {
					http.Error(w, "approved, but could not trust the host: "+err.Error(), http.StatusInternalServerError)
					return
				}
			}
			writeJSONResp(w, map[string]bool{"ok": true})
		})
	}
	mux.HandleFunc("POST /api/approve/{id}", resolve(true))
	mux.HandleFunc("POST /api/deny/{id}", resolve(false))
	mux.HandleFunc("GET /api/activity", u.auth(func(w http.ResponseWriter, r *http.Request) {
		act, err := loadActivity(u.receiptsFile, u.pubFile, 30)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSONResp(w, act)
	}))
	return loopbackOnly(mux)
}

// newPageToken returns a fresh random token for one `ovara run`.
func newPageToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// auth requires the page token as a bearer token. An empty page token
// (a misconfigured server) refuses everything rather than accepting "Bearer ".
func (u *uiServer) auth(h http.HandlerFunc) http.HandlerFunc {
	want := []byte("Bearer " + u.pageToken)
	return func(w http.ResponseWriter, r *http.Request) {
		got := []byte(r.Header.Get("Authorization"))
		if u.pageToken == "" || subtle.ConstantTimeCompare(got, want) != 1 {
			http.Error(w, "missing or wrong page token: open the link `ovara run` printed (it changes every time ovara run starts)", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		h(w, r)
	}
}

// loopbackOnly rejects requests whose Host is not a loopback name or IP,
// so a DNS-rebound hostname cannot be used to reach the page.
func loopbackOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.Trim(host, "[]")
		ip := net.ParseIP(host)
		if !strings.EqualFold(host, "localhost") && (ip == nil || !ip.IsLoopback()) {
			http.Error(w, "this page is only served to localhost", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSONResp(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
