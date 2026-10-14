package main

import (
	"net"
	"reflect"
	"testing"
)

// With a boundary the proxy is offered on loopback and the host's address
// on the boundary link; never on every interface.
func TestProxyListenAddrs(t *testing.T) {
	cases := []struct {
		listen, boundaryIP string
		want               []string
	}{
		{"127.0.0.1:9443", "", []string{"127.0.0.1:9443"}},
		{"127.0.0.1:9443", "10.200.7.1", []string{"127.0.0.1:9443", "10.200.7.1:9443"}},
		{"localhost:9443", boundaryDockerIP, []string{"localhost:9443", "172.30.0.1:9443"}},
		// an address the operator chose stays theirs
		{"10.0.0.5:9443", "10.200.7.1", []string{"10.0.0.5:9443"}},
	}
	for _, c := range cases {
		got := proxyListenAddrs(c.listen, c.boundaryIP)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("proxyListenAddrs(%q, %q) = %v, want %v", c.listen, c.boundaryIP, got, c.want)
		}
		for _, a := range got {
			host, _, _ := net.SplitHostPort(a)
			if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
				t.Errorf("listens on every interface: %s", a)
			}
		}
	}
	if got := boundaryProxyIP(boundarySubnetIdx("ovara-box")); net.ParseIP(got) == nil {
		t.Errorf("boundary address %q", got)
	}
}
