package proxy

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// A corporate network routes everything through its own proxy and often
// inspects TLS with its own CA. Ovara's outbound side can follow suit:
// its requests go to upstream_proxy, and the TLS it verifies trusts
// upstream_ca_bundle besides the system roots. The agent is not involved:
// it still talks to Ovara only, with Ovara's CA, and `ovara env` points it
// at Ovara, never at the corporate proxy.
//
// With an upstream proxy the destination's name is resolved by that proxy,
// not here, so the public-address guard checks what it can: an IP literal
// is still refused, and the proxy's own address (usually a private one) is
// dialled as given.

const schemeHTTP = "http"

// SetUpstream points Ovara's own requests at proxyURL (http://host:port or
// https://host:port, userinfo allowed; "" for none) and trusts the PEM
// certificates in caBundle for upstream TLS (nil for the system roots
// only). It applies to new connections.
func (s *Server) SetUpstream(proxyURL string, caBundle []byte) error {
	t := s.transport
	if proxyURL == "" {
		t.Proxy = nil
		s.upstreamHost = ""
	} else {
		u, err := url.Parse(proxyURL)
		if err != nil || (u.Scheme != schemeHTTP && u.Scheme != schemeHTTPS) || u.Hostname() == "" {
			return fmt.Errorf("upstream_proxy %q: want http://host:port or https://host:port", proxyURL)
		}
		port := u.Port()
		if port == "" {
			port = "80"
			if u.Scheme == schemeHTTPS {
				port = "443"
			}
		}
		t.Proxy = http.ProxyURL(u)
		s.upstreamHost = net.JoinHostPort(strings.ToLower(u.Hostname()), port)
	}
	if caBundle == nil {
		t.TLSClientConfig.RootCAs = nil
	} else {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(caBundle) {
			return errors.New("upstream_ca_bundle: no PEM certificate in the file")
		}
		t.TLSClientConfig.RootCAs = pool
	}
	t.CloseIdleConnections()
	return nil
}

// UpstreamDescription is the upstream proxy without its credentials, for
// a log line; "" when there is none.
func (s *Server) UpstreamDescription() string {
	if s.upstreamHost == "" || s.transport.Proxy == nil {
		return ""
	}
	u, err := s.transport.Proxy(&http.Request{URL: &url.URL{Scheme: "https", Host: "example.com"}})
	if err != nil || u == nil {
		return s.upstreamHost
	}
	c := *u
	c.User = nil
	return c.String()
}

// isUpstreamAddr reports the upstream proxy's own address, which the
// transport dials for every request when a proxy is set.
func (s *Server) isUpstreamAddr(addr string) bool {
	return s.upstreamHost != "" && strings.EqualFold(addr, s.upstreamHost)
}
