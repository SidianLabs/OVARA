package proxy

import (
	"bytes"
	"io"
)

// scrubReader streams a response body replacing every occurrence of the
// injected secret values with "[REDACTED]". Secrets can straddle read
// boundaries, so the tail of each window is carried into the next:
// anything within maxSecretLen-1 bytes of the end might be the prefix of a
// secret and is held back until more data (or EOF) disambiguates it.
type scrubReader struct {
	r       io.Reader
	secrets [][]byte
	maxLen  int
	carry   []byte // unflushed tail, always < maxLen bytes
	pending []byte // scrubbed output not yet consumed by Read
	eof     bool
	err     error
}

func newScrubReader(r io.Reader, secrets [][]byte) io.Reader {
	s := &scrubReader{r: r, secrets: secrets}
	for _, b := range secrets {
		if len(b) > s.maxLen {
			s.maxLen = len(b)
		}
	}
	return s
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
		data := replaceSecrets(append(s.carry, buf[:n]...), s.secrets)
		if err == io.EOF {
			s.eof = true
			s.pending = data
			s.carry = nil
		} else {
			hold := s.holdBack(data)
			s.pending = data[:len(data)-hold]
			s.carry = append([]byte(nil), data[len(data)-hold:]...)
		}
	}
	if err != nil {
		if err == io.EOF && !s.eof {
			s.eof = true
			s.pending = append(s.pending, replaceSecrets(s.carry, s.secrets)...)
			s.carry = nil
		}
		s.err = err
	}
}

// holdBack returns the length of the longest suffix of data (shorter than
// any secret) that equals the prefix of a secret — bytes that must not be
// emitted until the next read proves or disproves the match.
func (s *scrubReader) holdBack(data []byte) int {
	limit := s.maxLen - 1
	if limit > len(data) {
		limit = len(data)
	}
	for l := limit; l > 0; l-- {
		suffix := data[len(data)-l:]
		for _, secret := range s.secrets {
			if l < len(secret) && bytes.Equal(suffix, secret[:l]) {
				return l
			}
		}
	}
	return 0
}

func replaceSecrets(b []byte, secrets [][]byte) []byte {
	for _, secret := range secrets {
		if len(secret) == 0 {
			continue
		}
		b = bytes.ReplaceAll(b, secret, []byte("[REDACTED]"))
	}
	return b
}
