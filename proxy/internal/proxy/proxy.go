// Package proxy is the executor chokepoint: an HTTP forward proxy with
// CONNECT + MITM support. Every request is evaluated against the gateway,
// allowed requests have real credentials injected and are executed by the
// proxy itself, and every transit is receipted.
package proxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"ovara.proxy/internal/ca"
	"ovara.proxy/internal/creds"
	"ovara.proxy/internal/gateway"
	"ovara.proxy/internal/receipts"
)

type Server struct {
	ca      *ca.CA
	gw      *gateway.Client
	bindings []creds.Binding
	chain   *receipts.Chain
	failOpen bool
	transport *http.Transport
}

func New(c *ca.CA, gw *gateway.Client, bindings []creds.Binding, chain *receipts.Chain, failOpen bool) *Server {
	return &Server{
		ca: c, gw: gw, bindings: bindings, chain: chain, failOpen: failOpen,
		transport: &http.Transport{
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			MaxIdleConns:        100,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}
	// Plain-HTTP proxy request (absolute URI). Execute directly.
	s.handleRequest(w, r)
}

// handleConnect hijacks the tunnel and MITMs the TLS inside it.
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		return
	}
	if _, err := fmt.Fprint(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		client.Close()
		return
	}
	cert, err := s.ca.CertFor(host)
	if err != nil {
		log.Printf("mitm: cert for %s: %v", host, err)
		client.Close()
		return
	}
	// Advertise http/1.1 only; h2 policy granularity is future work.
	tlsConn := tls.Server(client, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"http/1.1"},
	})
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("mitm: handshake with client for %s: %v", host, err)
		client.Close()
		return
	}
	// Serve HTTP inside the TLS tunnel. One CONNECT = one host; keep-alive
	// handled by the one-shot server.
	listener := &oneShotListener{conn: tlsConn, done: make(chan struct{})}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Scheme = "https"
		r.URL.Host = host
		s.handleRequest(w, r)
	})}
	go srv.Serve(listener)
}

type oneShotListener struct {
	conn net.Conn
	done chan struct{}
	once bool
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	if l.once {
		<-l.done
		return nil, fmt.Errorf("closed")
	}
	l.once = true
	return l.conn, nil
}
func (l *oneShotListener) Close() error   { close(l.done); return l.conn.Close() }
func (l *oneShotListener) Addr() net.Addr { return l.conn.LocalAddr() }

// handleRequest evaluates, executes, and receipts one request.
func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	url := r.URL.String()
	decision := "error"
	status := 0
	defer func() {
		if _, err := s.chain.Record(r.Method, url, decision, status); err != nil {
			log.Printf("receipt: %v", err)
		}
	}()

	d, err := s.gw.Check(r.Context(), r.Method, url)
	if err != nil {
		log.Printf("gateway check failed for %s: %v", url, err)
		if !s.failOpen {
			decision = "deny"
			http.Error(w, `{"error":"gateway unreachable, fail-closed"}`, http.StatusBadGateway)
			return
		}
		d = &gateway.Decision{Decision: "allow"}
	}
	decision = d.Decision

	switch d.Decision {
	case "deny":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, `{"error":"action denied","decision_id":%q,"reasons":%v}`, d.DecisionID, d.ReasonCodes)
		return
	case "escalate":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, `{"error":"action requires approval","decision_id":%q,"reasons":%v}`, d.DecisionID, d.ReasonCodes)
		return
	}

	// allow: inject real credentials for this host, execute on behalf.
	host := r.URL.Hostname()
	if headers := creds.Match(s.bindings, host); headers != nil {
		for k, v := range headers {
			r.Header.Set(k, v)
		}
	}
	r.RequestURI = ""
	r.Header.Del("Proxy-Connection")
	r.Header.Del("Proxy-Authorization")
	resp, err := s.transport.RoundTrip(r)
	if err != nil {
		decision = "error"
		http.Error(w, fmt.Sprintf("upstream error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	status = resp.StatusCode
	for k, vv := range resp.Header {
		for _, v := range vv {
			if strings.EqualFold(k, "Transfer-Encoding") {
				continue
			}
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
