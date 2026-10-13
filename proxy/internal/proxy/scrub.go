package proxy

import (
	"io"
	"log"
	"mime"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

const redactedMark = "[REDACTED]"

// secretSet matches injected secret spellings case-insensitively (ASCII):
// a reflector that upper-cases a header value, or a hex dump in capitals,
// must not slip past. Targets are kept lower-case and longest first, so a
// whole spelling is redacted in one piece rather than around a shorter one.
type secretSet struct {
	targets [][]byte
	first   [256]bool // possible first bytes of a target (lower-case)
	maxLen  int
}

func newSecretSet(secrets [][]byte) *secretSet {
	m := &secretSet{}
	seen := map[string]bool{}
	for _, s := range secrets {
		if len(s) == 0 {
			continue
		}
		l := asciiLower(s)
		if seen[string(l)] {
			continue
		}
		seen[string(l)] = true
		m.targets = append(m.targets, l)
		m.first[l[0]] = true
		if len(l) > m.maxLen {
			m.maxLen = len(l)
		}
	}
	sort.SliceStable(m.targets, func(i, j int) bool { return len(m.targets[i]) > len(m.targets[j]) })
	return m
}

func lowerByte(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

// asciiLower lower-cases ASCII letters only, so lengths and offsets are
// unchanged (bytes.ToLower may change the length of non-UTF-8 input).
func asciiLower(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = lowerByte(c)
	}
	return out
}

// hasPrefixFold reports whether b starts with t (t lower-case).
func hasPrefixFold(b, t []byte) bool {
	if len(b) < len(t) {
		return false
	}
	for i, c := range t {
		if lowerByte(b[i]) != c {
			return false
		}
	}
	return true
}

// match returns the length of the target that starts at b[0], or 0.
func (m *secretSet) match(b []byte) int {
	if len(b) == 0 || !m.first[lowerByte(b[0])] {
		return 0
	}
	for _, t := range m.targets {
		if hasPrefixFold(b, t) {
			return len(t)
		}
	}
	return 0
}

// replace returns b with every target replaced by the redaction mark. b is
// returned as is when nothing matches.
func (m *secretSet) replace(b []byte) []byte {
	if m == nil || len(m.targets) == 0 {
		return b
	}
	var out []byte
	last := 0
	for i := 0; i < len(b); {
		n := m.match(b[i:])
		if n == 0 {
			i++
			continue
		}
		if out == nil {
			out = make([]byte, 0, len(b))
		}
		out = append(out, b[last:i]...)
		out = append(out, redactedMark...)
		i += n
		last = i
	}
	if out == nil {
		return b
	}
	return append(out, b[last:]...)
}

func (m *secretSet) contains(s string) bool {
	if m == nil {
		return false
	}
	for i := 0; i < len(s); i++ {
		if m.match([]byte(s[i:])) > 0 {
			return true
		}
	}
	return false
}

// holdBack returns the length of the longest suffix of data (shorter than
// any secret) that equals the prefix of a secret — bytes that must not be
// emitted until the next read proves or disproves the match.
func (m *secretSet) holdBack(data []byte) int {
	limit := m.maxLen - 1
	if limit > len(data) {
		limit = len(data)
	}
	for l := limit; l > 0; l-- {
		suffix := data[len(data)-l:]
		for _, t := range m.targets {
			if l < len(t) && hasPrefixFold(suffix, t[:l]) {
				return l
			}
		}
	}
	return 0
}

// scrubReader streams a response body replacing every occurrence of the
// injected secret values with "[REDACTED]". Secrets can straddle read
// boundaries, so the tail of each window is carried into the next:
// anything within maxSecretLen-1 bytes of the end might be the prefix of a
// secret and is held back until more data (or EOF) disambiguates it.
type scrubReader struct {
	r       io.Reader
	set     *secretSet
	carry   []byte // unflushed tail, always < maxLen bytes
	pending []byte // scrubbed output not yet consumed by Read
	eof     bool
	err     error
}

func newScrubReader(r io.Reader, secrets [][]byte) io.Reader {
	return &scrubReader{r: r, set: newSecretSet(secrets)}
}

func (s *scrubReader) Read(p []byte) (int, error) {
	for len(s.pending) == 0 && s.err == nil {
		s.fill()
	}
	n := copy(p, s.pending)
	s.pending = s.pending[n:]
	if len(s.pending) == 0 && len(p) > n {
		// drained and nothing else may come
		if s.err != nil {
			return n, s.err
		}
	}
	return n, nil
}

var scrubBufSize = 64 * 1024

// fill reads one chunk and produces scrubbed output. Complete secret
// matches are replaced first; then, unless at EOF, any trailing bytes that
// could be the head of a secret straddling the next read are held in carry
// — a secret's straddling head is always a suffix of the data read so far.
func (s *scrubReader) fill() {
	buf := make([]byte, scrubBufSize)
	n, err := s.r.Read(buf)
	if n > 0 {
		data := s.set.replace(append(s.carry, buf[:n]...))
		if err == io.EOF {
			s.eof = true
			s.pending = data
			s.carry = nil
		} else {
			hold := s.set.holdBack(data)
			s.pending = data[:len(data)-hold]
			s.carry = append([]byte(nil), data[len(data)-hold:]...)
		}
	}
	if err != nil {
		if err == io.EOF && !s.eof {
			s.eof = true
			s.pending = append(s.pending, s.set.replace(s.carry)...)
			s.carry = nil
		}
		s.err = err
	}
}

// signedParam finds query parameters that carry a credential of their own:
// presigned storage URLs (S3, GCS, Azure SAS), download links with a token,
// and the like. An upstream answering a credentialed request may mint them
// from the injected key (a redirect to a signed archive URL, a JSON field
// holding a download link); each works without the key, so it is redacted
// on the way to the agent. The parameter separator may be JSON-escaped
// ("&") or HTML-escaped ("&amp;"); a value ends at a delimiter, a quote,
// whitespace or a backslash (the start of a JSON escape).
var signedParam = regexp.MustCompile(`(?i)((?:[?&]|\\u0026|&amp;)(?:x-amz-signature|x-amz-credential|x-amz-security-token|x-goog-signature|x-goog-credential|sig|signature|token|access_token|jwt)=)[^&"'\s<>\\]+`)

// signedParamKeyMax bounds how far before the end of a chunk an incomplete
// key ("&x-amz-security-token=") can start.
const signedParamKeyMax = 32

func isSignedParamValueByte(c byte) bool {
	switch c {
	case '&', '"', '\'', '<', '>', '\\', ' ', '\t', '\n', '\r', '\f', '\v':
		return false
	}
	return true
}

func scrubSignedParams(s string) string {
	return signedParam.ReplaceAllString(s, "${1}"+redactedMark)
}

// signedParamReader redacts signedParam values from a streamed body. A key
// cut by a read boundary is carried into the next read; a value cut by one
// is redacted at once and whatever continues it at the start of the next
// read is dropped, so no window has to hold a whole value.
type signedParamReader struct {
	r       io.Reader
	carry   []byte
	pending []byte
	inValue bool // the last chunk ended inside a redacted value
	err     error
}

func newSignedParamReader(r io.Reader) io.Reader { return &signedParamReader{r: r} }

func (s *signedParamReader) Read(p []byte) (int, error) {
	for len(s.pending) == 0 && s.err == nil {
		s.fill()
	}
	n := copy(p, s.pending)
	s.pending = s.pending[n:]
	if len(s.pending) == 0 && s.err != nil {
		return n, s.err
	}
	return n, nil
}

func (s *signedParamReader) fill() {
	buf := make([]byte, scrubBufSize)
	n, err := s.r.Read(buf)
	data := append(append(make([]byte, 0, len(s.carry)+n), s.carry...), buf[:n]...)
	s.carry = nil
	if s.inValue {
		i := 0
		for i < len(data) && isSignedParamValueByte(data[i]) {
			i++
		}
		data = data[i:]
		if len(data) > 0 || err != nil {
			s.inValue = false
		}
	}
	if err != nil {
		s.pending = signedParam.ReplaceAll(data, []byte("${1}"+redactedMark))
		s.err = err
		return
	}
	cut := len(data) - signedParamKeyMax
	if cut < 0 {
		cut = 0
	}
	locs := signedParam.FindAllIndex(data, -1)
	if k := len(locs); k > 0 && locs[k-1][1] == len(data) {
		// The last value runs to the end of what has been read.
		cut = len(data)
		s.inValue = true
	} else {
		for _, l := range locs {
			if l[0] < cut && l[1] > cut {
				cut = l[1]
			}
		}
	}
	s.pending = signedParam.ReplaceAll(data[:cut], []byte("${1}"+redactedMark))
	s.carry = append([]byte(nil), data[cut:]...)
}

// textualType reports whether a body of this Content-Type is text in which
// URLs are rewritten (JSON, XML, HTML, plain text, form data). Other
// bodies are left alone: rewriting bytes in an archive would corrupt it.
func textualType(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	switch {
	case strings.HasPrefix(mt, "text/"),
		mt == "application/json", strings.HasSuffix(mt, "+json"),
		mt == "application/xml", strings.HasSuffix(mt, "+xml"),
		mt == "application/javascript", mt == "application/x-www-form-urlencoded",
		mt == "application/x-ndjson":
		return true
	}
	return false
}

// copyScrubbedHeader copies src into dst under prefix (http.TrailerPrefix
// for trailers). On a credentialed response (set != nil) secret spellings
// and signed URL parameters are redacted from values, and a header whose
// NAME carries a secret is dropped: a name cannot hold "[REDACTED]".
func copyScrubbedHeader(dst, src http.Header, prefix string, set *secretSet) {
	for k, vv := range src {
		if set != nil && set.contains(k) {
			log.Printf("dropped a response header whose name carries an injected credential")
			continue
		}
		for _, v := range vv {
			if set != nil {
				v = scrubSignedParams(string(set.replace([]byte(v))))
			}
			dst[prefix+k] = append(dst[prefix+k], v)
		}
	}
}
