package main

import (
	"crypto/x509"
	"net/url"
	"os"

	"ovara.proxy/internal/config"
)

const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

// auditUpstream checks the corporate-network settings offline: the proxy
// URL parses, the CA bundle is there and holds certificates, and a proxy
// set in this shell's environment is not silently unused.
func auditUpstream(dir string, cfg *config.Config) []check {
	var out []check
	if cfg.UpstreamProxy != "" {
		u, err := url.Parse(cfg.UpstreamProxy)
		switch {
		case err != nil || (u.Scheme != schemeHTTP && u.Scheme != schemeHTTPS) || u.Hostname() == "":
			out = append(out, check{"upstream proxy", "FAIL", "upstream_proxy is not http(s)://host:port"})
		case u.User != nil && u.User.Username() != "":
			out = append(out, check{"upstream proxy", "PASS", u.Scheme + "://" + u.Host + " with proxy credentials (Ovara's own requests go through it; the agent still talks to Ovara only)"})
		default:
			out = append(out, check{"upstream proxy", "PASS", u.Scheme + "://" + u.Host + " (Ovara's own requests go through it; the agent still talks to Ovara only)"})
		}
	} else if name := proxyInEnvironment(); name != "" {
		out = append(out, check{"upstream proxy", "WARN", name + " is set in this shell but proxy.json has no upstream_proxy: Ovara's own requests will not use it"})
	}
	if cfg.UpstreamCABundle != "" {
		path := inDir(dir, cfg.UpstreamCABundle)
		b, err := os.ReadFile(path) //nolint:gosec // the operator's own file, named in proxy.json
		switch {
		case err != nil:
			out = append(out, check{"upstream CA bundle", "FAIL", "cannot read " + path + ": " + err.Error()})
		case !x509.NewCertPool().AppendCertsFromPEM(b):
			out = append(out, check{"upstream CA bundle", "FAIL", path + " holds no PEM certificate"})
		default:
			out = append(out, check{"upstream CA bundle", "PASS", path + " is trusted for the TLS Ovara verifies, besides the system roots (the agent sees Ovara's CA only)"})
		}
	}
	return out
}

// proxyInEnvironment names the first proxy variable set in this shell.
func proxyInEnvironment() string {
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		if os.Getenv(k) != "" {
			return k
		}
	}
	return ""
}
