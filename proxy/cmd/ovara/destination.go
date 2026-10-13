package main

import (
	"net"
	"strings"
	"unicode/utf8"
)

// Where a request goes, said so a person cannot misread it. A URL such as
// https://api.github.com.attacker-cdn.io/repos/acme/app/pulls starts with a
// name the person trusts; the part that decides who receives the data is
// the registrable domain, attacker-cdn.io, in the middle. The approval
// shows that domain on its own line, and whether the host is one of the
// read hosts Ovara trusts by default.

// destination describes the receiving end of an http.request resource.
type destination struct {
	Domain  string // registrable domain ("attacker-cdn.io"), or the IP address
	Host    string // the full host name
	Trusted bool   // on the default trusted read or git list
	Note    string // a warning about the host itself, or ""
}

// destinationOf parses "METHOD scheme://host[:port]/path ..." (and the
// proxy's "METHOD UNAUTH host:port"). ok is false for resources that are
// not network requests (commit:, shell:, npm:, ...).
func destinationOf(resource string) (d destination, ok bool) {
	method, rest, found := strings.Cut(resource, " ")
	if !found || method == "" || strings.Trim(method, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") != "" {
		return d, false
	}
	target, extra, _ := strings.Cut(rest, " ")
	var authority string
	if target == "UNAUTH" {
		authority = extra
	} else {
		i := strings.Index(target, "://")
		if i <= 0 {
			return d, false
		}
		authority = target[i+3:]
		if j := strings.IndexAny(authority, "/?#"); j >= 0 {
			authority = authority[:j]
		}
	}
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		authority = authority[at+1:]
	}
	host := authority
	if h, _, err := net.SplitHostPort(authority); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.ToLower(strings.Trim(host, "[]")), ".")
	if host == "" {
		return d, false
	}
	d.Host = host
	if net.ParseIP(host) != nil {
		d.Domain = host
		d.Note = "an IP address, not a name"
		return d, true
	}
	d.Domain = registrableDomain(host)
	for _, h := range append(append([]string{}, trustedReadHosts...), trustedGitHosts...) {
		if h == host {
			d.Trusted = true
		}
	}
	if strings.Contains(host, "%") || strings.Contains(host, "xn--") || !isASCII(host) {
		d.Note = "the name has non-ASCII or encoded characters: it may imitate another name"
	}
	return d, true
}

// line is the destination as one line for the approval:
// "→ to attacker-cdn.io (host api.github.com.attacker-cdn.io; not a default-trusted host)".
func (d destination) line() string {
	var notes []string
	if d.Host != d.Domain {
		notes = append(notes, "host "+d.Host)
	}
	if d.Trusted {
		notes = append(notes, "a default-trusted host")
	} else {
		notes = append(notes, "not a default-trusted host")
	}
	s := "→ to " + d.Domain + " (" + strings.Join(notes, "; ") + ")"
	if d.Note != "" {
		s += " ⚠ " + d.Note
	}
	return s
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// registrableDomain is the name an owner registers: the last two labels,
// or three under a public suffix of two labels (example.co.uk), or one
// more than a hosting suffix where anyone can get a name of their own
// (someone.github.io). This is a short list, not the Public Suffix List
// (golang.org/x/net/publicsuffix is not a dependency of this module); a
// suffix it does not know is shown with one label too few, never with a
// name the request does not contain.
func registrableDomain(host string) string {
	labels := strings.Split(host, ".")
	if len(labels) <= 2 {
		return host
	}
	best := 1 // labels in the public suffix
	for n := 2; n <= 3 && n < len(labels); n++ {
		if publicSuffixes[strings.Join(labels[len(labels)-n:], ".")] {
			best = n
		}
	}
	return strings.Join(labels[len(labels)-best-1:], ".")
}

var publicSuffixes = func() map[string]bool {
	m := map[string]bool{}
	for _, s := range strings.Fields(`
		co.uk org.uk ac.uk gov.uk me.uk net.uk ltd.uk plc.uk sch.uk nhs.uk
		com.au net.au org.au edu.au gov.au id.au
		co.nz net.nz org.nz govt.nz ac.nz
		co.jp ne.jp or.jp ac.jp go.jp
		com.br net.br org.br gov.br
		com.cn net.cn org.cn gov.cn edu.cn
		co.in net.in org.in firm.in gen.in ind.in gov.in ac.in
		co.za org.za gov.za
		com.mx org.mx gob.mx com.ar com.tr com.tw org.tw com.hk org.hk com.sg com.my
		co.kr or.kr co.il org.il com.ua com.pl co.id com.ph com.vn com.eg com.sa com.pk com.ng
		co.th in.th com.co com.pe com.ec com.uy
		github.io gitlab.io githubusercontent.com herokuapp.com vercel.app netlify.app
		pages.dev workers.dev web.app firebaseapp.com appspot.com azurewebsites.net
		cloudfront.net s3.amazonaws.com ngrok.io ngrok-free.app ngrok.app trycloudflare.com
		onrender.com fly.dev glitch.me repl.co replit.dev blogspot.com r2.dev deno.dev
		surge.sh readthedocs.io azurestaticapps.net pythonanywhere.com
	`) {
		m[s] = true
	}
	return m
}()
