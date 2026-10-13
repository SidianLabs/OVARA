package proxy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"unicode"
)

// parseRefUpdates reads an agent-controlled request body. Whatever it is
// fed, it must not panic or hang, and every ref it reports is one name
// (no white space, no NUL) under refs/, whose delete flag matches its new
// object id. (Whether "incomplete" parses are treated as a deny is the
// caller's job and is covered by the git gate tests.)
func FuzzParseRefUpdates(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("0000"))
	f.Add([]byte("0067" + "0000000000000000000000000000000000000000 1111111111111111111111111111111111111111 refs/heads/main\x00 report-status"))
	f.Add([]byte("zzzz not pkt-line"))
	f.Add([]byte("ffff"))
	f.Add([]byte("0004" + "0000"))
	f.Add([]byte("003f1111111111111111111111111111111111111111 0000000000000000000000000000000000000000 refs/heads/x y\n0000"))
	f.Fuzz(func(t *testing.T, body []byte) {
		refs, _ := parseRefUpdates(body)
		for _, r := range refs {
			if !strings.HasPrefix(r.Ref, "refs/") || strings.ContainsFunc(r.Ref, func(c rune) bool { return c == 0 || unicode.IsSpace(c) }) {
				t.Fatalf("ref %q from %q is not one ref name", r.Ref, body)
			}
			if r.Delete != (strings.Trim(r.NewSHA, "0") == "") {
				t.Fatalf("delete flag %v for new id %q", r.Delete, r.NewSHA)
			}
		}
	})
}

// A push git would send is read back exactly: the ref it names, its ids
// and whether it deletes, with the header complete.
func FuzzParseRefUpdatesRoundTrip(f *testing.F) {
	f.Add("refs/heads/main", "0000000000000000000000000000000000000000", "1111111111111111111111111111111111111111", "report-status side-band-64k")
	f.Add("refs/heads/feature/x", "1111111111111111111111111111111111111111", "0000000000000000000000000000000000000000", "")
	f.Add("refs/tags/v1.0", "a", "b", "agent=git/2.4")
	f.Fuzz(func(t *testing.T, ref, oldID, newID, caps string) {
		bad := func(s string) bool {
			return s == "" || strings.ContainsFunc(s, func(c rune) bool { return c == 0 || unicode.IsSpace(c) })
		}
		if bad(ref) || bad(oldID) || bad(newID) || !strings.HasPrefix(ref, "refs/") || strings.ContainsRune(caps, '\n') {
			return
		}
		line := oldID + " " + newID + " " + ref + "\x00" + caps + "\n"
		if len(line)+4 > 0xffff {
			return
		}
		body := []byte(fmt.Sprintf("%04x%s0000PACK\x00\x00\x00\x02", len(line)+4, line))
		refs, complete := parseRefUpdates(body)
		if !complete || len(refs) != 1 {
			t.Fatalf("%q: complete=%v refs=%+v", body, complete, refs)
		}
		r := refs[0]
		if r.Ref != ref || r.OldSHA != oldID || r.NewSHA != newID || r.Delete != (strings.Trim(newID, "0") == "") {
			t.Fatalf("%q read back as %+v", body, r)
		}
	})
}

// validUploadPackRequest also reads an agent-controlled body. A body it
// accepts is pkt-line text and nothing else: no byte outside printable
// ASCII and the line feed, so binary data cannot ride along with a fetch.
func FuzzValidUploadPackRequest(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("0000"))
	f.Add([]byte("0032want 0000000000000000000000000000000000000000\n0000"))
	f.Add([]byte("0012command=fetch\n00010009done\n0000"))
	f.Add([]byte("0003"))
	f.Add([]byte("0032want 0000000000000000000000000000000000000000\n0009done\x00"))
	f.Add([]byte("0012command=fetch\n0001000ffilter blob\x01\n0000"))
	f.Fuzz(func(t *testing.T, body []byte) {
		if !validUploadPackRequest(body) {
			return
		}
		for _, c := range body {
			if (c < 0x20 || c > 0x7e) && c != '\n' {
				t.Fatalf("accepted %q with byte %#x", body, c)
			}
		}
	})
}

func FuzzNormalizeHost(f *testing.F) {
	for _, s := range []string{"", "a.b", "A.B.", "[::1]:443", "host:99999", "..", "x:y:z", "\x00"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		a := normalizeHost(s)
		// Idempotent: normalizing twice must not change the result, or two
		// code paths could disagree about whether a host is "sensitive".
		if b := normalizeHost(a); b != a {
			t.Fatalf("normalizeHost not idempotent: %q -> %q -> %q", s, a, b)
		}
	})
}

// A read (GET or HEAD, however the client spelled the method) that carries
// a body, or more path, query and forwarded header bytes than the read
// budget, is refused. Other methods are not this check's business.
func FuzzReadCarriesData(f *testing.F) {
	f.Add("GET", "/x", "a=b", "X-Data", "v", int64(0), false)
	f.Add("get", "/x", "", "Accept", strings.Repeat("a", 300), int64(0), false)
	f.Add("HeAd", "/", "", "X-Exfil", strings.Repeat("A", 3000), int64(0), false)
	f.Add("GET", "/"+strings.Repeat("p", 2100), "", "", "", int64(0), false)
	f.Add("GET", "/x", strings.Repeat("q", 600), "", "", int64(0), false)
	f.Add("GET", "/x", "", "", "", int64(5), false)
	f.Add("gEt", "/x", "", "", "", int64(0), true)
	f.Add("POST", "/x", "", "X-Data", strings.Repeat("A", 3000), int64(10), false)
	f.Add("GET", "/x", "", "Proxy-Authorization", strings.Repeat("A", 3000), int64(0), false)
	f.Fuzz(func(t *testing.T, method, path, query, hname, hval string, contentLength int64, chunked bool) {
		s := &Server{limits: defaultLimits()}
		u := &url.URL{Scheme: "http", Host: "x", Path: path, RawQuery: query}
		r := &http.Request{Method: method, URL: u, Header: http.Header{}, ContentLength: contentLength}
		if chunked {
			r.TransferEncoding = []string{"chunked"}
		}
		if hname != "" {
			r.Header[hname] = []string{hval}
		}
		why := s.readCarriesData(r)
		isRead := strings.EqualFold(method, http.MethodGet) || strings.EqualFold(method, http.MethodHead)
		if !isRead {
			if why != "" {
				t.Fatalf("non-read %q refused as a read: %s", method, why)
			}
			return
		}
		mustRefuse := ""
		switch {
		case contentLength > 0 || chunked:
			mustRefuse = "a body"
		case len(query) > maxReadQueryBytes:
			mustRefuse = "a long query"
		case len(u.EscapedPath())+len(query) > s.limits.maxReadRequest:
			mustRefuse = "a long path and query"
		case hname != "" && !notForwarded(hname) && !standardHeaders[http.CanonicalHeaderKey(hname)] &&
			len(hname)+len(hval) > s.limits.maxReadRequest:
			mustRefuse = "a large header"
		}
		if mustRefuse != "" && why == "" {
			t.Fatalf("%s %s?%s with %s (header %q, %d bytes) was not refused", method, path, query, mustRefuse, hname, len(hval))
		}
	})
}

// modelKeys are the keys an injected feature is nested under: none of them
// is one the gate skips on purpose (tool inputs and schemas).
var modelKeys = []string{"messages", "content", "tools", "x", "Input", "params", "metadata", "type", "data"}

// The model gate, whatever JSON surrounds them: a non-empty "mcp_servers"
// or a {"type":"url"} source anywhere outside a tool call's input is found.
// Arbitrary JSON never panics the walk.
func FuzzModelValueRefusal(f *testing.F) {
	f.Add([]byte(`{"model":"m","messages":[]}`), []byte{0, 2, 1}, "https://x.example/sse", uint8(0))
	f.Add([]byte(`{"model":"m","messages":[{"role":"user","content":[{"type":"tool_result","content":[]}]}]}`), []byte{3, 1}, "https://x.example/a.png", uint8(1))
	f.Add([]byte(`{"tools":[{"name":"f","input_schema":{"type":"url"}}]}`), []byte{}, "x", uint8(0))
	f.Add([]byte(`[1, "a", null, true, {"a": {"b": [ {} ]}}]`), []byte{8, 9, 1, 1, 1}, "", uint8(1))
	f.Add([]byte(`not json`), []byte{4}, "u", uint8(0))
	f.Fuzz(func(t *testing.T, doc, path []byte, val string, kind uint8) {
		var v any
		dec := json.NewDecoder(bytes.NewReader(doc))
		dec.UseNumber()
		if dec.Decode(&v) != nil {
			v = nil
		}
		_ = modelValueRefusal(v)

		var inner any
		if kind&1 == 0 {
			inner = map[string]any{"mcp_servers": []any{map[string]any{"type": "url", "url": val}}}
		} else {
			inner = map[string]any{"type": "image", "source": map[string]any{"type": "url", "url": val}}
		}
		if len(path) > 12 {
			path = path[:12]
		}
		for _, b := range path {
			if b&1 == 1 {
				inner = []any{v, inner}
			} else {
				inner = map[string]any{modelKeys[int(b>>1)%len(modelKeys)]: inner, "other": v}
			}
		}
		// The request goes over the wire as JSON and is decoded again.
		raw, err := json.Marshal(inner)
		if err != nil {
			return
		}
		var got any
		dec = json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&got); err != nil {
			t.Fatalf("re-decode %s: %v", raw, err)
		}
		if modelValueRefusal(got) == "" {
			t.Fatalf("not refused: %s", raw)
		}
	})
}

// The approver's preview masks what it cannot show. Whatever the text, it
// does not panic, a base64 secret of 40+ characters placed anywhere in it
// is not in the output, and the count says something was masked.
func FuzzRedactPreviewCount(f *testing.F) {
	f.Add("data= end", []byte("0123456789abcdefghijklmnopqrstuvwxyz0123"), uint16(5))
	f.Add(`{"user":"ana","password":"hunter2hunter2","note":"hi"}`, []byte("k"), uint16(30))
	f.Add("q=golang+generics&page=2", []byte("\xff\xfe\x00\x01"), uint16(2))
	f.Add("Authorization: Bearer ", []byte("ghp_0123456789abcdef0123456789"), uint16(22))
	f.Add("token=", []byte("sk-0123456789abcdef"), uint16(6))
	f.Fuzz(func(t *testing.T, s string, seed []byte, pos uint16) {
		_, _ = redactPreviewCount(s)

		// 30 bytes or more encode to 40 or more base64 characters.
		for len(seed) < 30 {
			seed = append(seed, byte(len(seed)*37+11))
		}
		if len(seed) > 300 {
			seed = seed[:300]
		}
		secret := base64.StdEncoding.EncodeToString(seed)
		at := int(pos) % (len(s) + 1)
		in := s[:at] + secret + s[at:]
		out, n := redactPreviewCount(in)
		if strings.Contains(out, secret) {
			t.Fatalf("secret %q survived in %q", secret, out)
		}
		if n < 1 {
			t.Fatalf("secret in %q, but nothing counted as masked (out %q)", in, out)
		}
	})
}
