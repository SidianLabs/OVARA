package mcp

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
)

// Server-Sent Events, read the way the event-stream specification says:
// lines end in CRLF, LF or a lone CR; an event ends at a blank line; a
// leading byte order mark is ignored. Clients follow those rules, so a
// checker that only split on LF could be shown one event while the client
// reads two.

// ErrEventTooLarge reports an event longer than the reader's bound.
var ErrEventTooLarge = errors.New("server-sent event too large to check")

var bom = []byte("\xef\xbb\xbf")

// EventReader reads raw events from a stream.
type EventReader struct {
	r     *bufio.Reader
	max   int
	first bool
}

// NewEventReader reads events of at most max bytes from r.
func NewEventReader(r io.Reader, max int) *EventReader {
	return &EventReader{r: bufio.NewReaderSize(r, 32<<10), max: max, first: true}
}

// Next returns the bytes of the next event exactly as they arrived, up to
// and including the blank line that ends it. At the end of the stream it
// returns what is left (an event that was never ended, which clients drop)
// with io.EOF. An event over the bound is returned as far as it was read,
// with ErrEventTooLarge; Rest then continues the stream from there.
func (e *EventReader) Next() ([]byte, error) {
	var raw []byte
	lineLen := 0
	defer func() { e.first = false }()
	for {
		c, err := e.r.ReadByte()
		if err != nil {
			if err == io.EOF && len(raw) == 0 {
				return nil, io.EOF
			}
			return raw, err
		}
		raw = append(raw, c)
		if len(raw) > e.max {
			return raw, ErrEventTooLarge
		}
		switch c {
		case '\r':
			if nx, err := e.r.Peek(1); err == nil && nx[0] == '\n' {
				b, _ := e.r.ReadByte()
				raw = append(raw, b)
			}
			fallthrough
		case '\n':
			if lineLen == 0 {
				return raw, nil
			}
			lineLen = 0
		default:
			// the stream's leading BOM is not part of the first line
			if !(e.first && len(raw) <= len(bom) && bytes.HasPrefix(bom, raw)) {
				lineLen++
			}
		}
	}
}

// Rest is the stream after the last event returned.
func (e *EventReader) Rest() io.Reader { return e.r }

// Event is one parsed event.
type Event struct {
	Name    string // "event:" field ("" means "message")
	Data    string
	HasData bool
}

// ParseEvent reads the fields of one raw event.
func ParseEvent(raw []byte) Event {
	s := string(bytes.TrimPrefix(raw, bom))
	var ev Event
	var data strings.Builder
	for len(s) > 0 {
		i := strings.IndexAny(s, "\r\n")
		line := s
		if i >= 0 {
			line = s[:i]
			if s[i] == '\r' && i+1 < len(s) && s[i+1] == '\n' {
				i++
			}
			s = s[i+1:]
		} else {
			s = ""
		}
		if line == "" || line[0] == ':' {
			continue
		}
		field, value, found := strings.Cut(line, ":")
		if found {
			value = strings.TrimPrefix(value, " ")
		}
		switch field {
		case "data":
			data.WriteString(value)
			data.WriteByte('\n')
			ev.HasData = true
		case "event":
			ev.Name = value
		}
	}
	ev.Data = strings.TrimSuffix(data.String(), "\n")
	return ev
}

// MessageEvent is an event carrying one JSON-RPC message.
func MessageEvent(msg []byte) []byte {
	return append(append([]byte("event: message\ndata: "), msg...), '\n', '\n')
}
