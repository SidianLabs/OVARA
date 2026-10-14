package receipts

// Long runs: the chain is split into segments so one file does not grow
// without end. Before a receipt is appended to a current file that has
// reached the segment size, the file is synced, compressed into
// <name>.000001.jsonl.gz (then .000002, ...) and emptied; the next receipt
// continues the same chain, its prev_hash the hash of the segment's last
// line. Ovara never deletes a segment. Readers and the verifier walk every
// segment in order and then the current file; a segment missing from the
// front or the middle fails verification, like any other cut.

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// DefaultSegmentBytes is the current file's size at which it is compressed
// into a segment.
const DefaultSegmentBytes int64 = 64 << 20

var errStopWalk = errors.New("stop")

// SetRotation sets the segment size (0 or less: never rotate).
func (c *Chain) SetRotation(maxBytes int64) {
	c.mu.Lock()
	c.segmentBytes = maxBytes
	c.mu.Unlock()
}

type segmentFile struct {
	n    int
	name string
}

func segmentPattern(path string) *regexp.Regexp {
	base := strings.TrimSuffix(filepath.Base(path), ".jsonl")
	return regexp.MustCompile(`^` + regexp.QuoteMeta(base) + `\.(\d{6})\.jsonl\.gz$`)
}

// segmentsOf lists the chain's segment files, oldest first.
func segmentsOf(path string) []segmentFile {
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		return nil
	}
	re := segmentPattern(path)
	var segs []segmentFile
	for _, e := range entries {
		if m := re.FindStringSubmatch(e.Name()); m != nil {
			n, _ := strconv.Atoi(m[1])
			segs = append(segs, segmentFile{n, filepath.Join(filepath.Dir(path), e.Name())})
		}
	}
	sort.Slice(segs, func(i, j int) bool { return segs[i].n < segs[j].n })
	return segs
}

// missingSegment is the number of the first segment that should be there
// and is not (they are numbered from 1 without gaps), or 0.
func missingSegment(segs []segmentFile) int {
	for i, s := range segs {
		if s.n != i+1 {
			return i + 1
		}
	}
	return 0
}

// SegmentFiles returns the compressed segments of the chain at path,
// oldest first (the current file is not among them).
func SegmentFiles(path string) []string {
	segs := segmentsOf(path)
	out := make([]string, 0, len(segs))
	for _, s := range segs {
		out = append(out, s.name)
	}
	return out
}

func segmentName(path string, n int) string {
	return fmt.Sprintf("%s.%06d.jsonl.gz", strings.TrimSuffix(path, ".jsonl"), n)
}

// ForEachLine calls fn with every receipt line of the chain at path, oldest
// first: the segments, then the current file. fn must not keep the slice.
// A chain that does not exist yet has no lines.
func ForEachLine(path string, fn func(line []byte) error) error {
	for _, s := range SegmentFiles(path) {
		if err := eachLineOf(s, true, fn); err != nil {
			return err
		}
	}
	err := eachLineOf(path, false, fn)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func eachLineOf(path string, gz bool, fn func([]byte) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var r io.Reader = f
	if gz {
		zr, err := gzip.NewReader(f)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		defer zr.Close()
		r = zr
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 8<<20)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		if err := fn(sc.Bytes()); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// lastLineOf is the last receipt line of a segment.
func lastLineOf(segment string) ([]byte, error) {
	var last []byte
	if err := eachLineOf(segment, true, func(l []byte) error {
		last = append(last[:0], l...)
		return nil
	}); err != nil {
		return nil, err
	}
	if len(last) == 0 {
		return nil, errors.New("empty segment")
	}
	return last, nil
}

// countLines is the number of receipts in these segments.
func countLines(segs []string) int {
	n := 0
	for _, s := range segs {
		_ = eachLineOf(s, true, func([]byte) error { n++; return nil })
	}
	return n
}

// Count is the number of receipts in the whole chain at path, segments
// included (0 when there is no chain yet).
func Count(path string) int {
	n := 0
	_ = ForEachLine(path, func([]byte) error { n++; return nil })
	return n
}

// Size is the bytes the chain takes on disk, the current file and every
// segment, and how many segments there are.
func Size(path string) (total int64, segments int) {
	for _, s := range SegmentFiles(path) {
		if st, err := os.Stat(s); err == nil {
			total += st.Size()
			segments++
		}
	}
	if st, err := os.Stat(path); err == nil {
		total += st.Size()
	}
	return total, segments
}

// rotateIfFullLocked makes a segment of the current file when it has
// reached the segment size, before the next receipt is written to it. A
// rotation that fails costs nothing but a bigger file: the receipt goes to
// the current file as before. Called with c.mu held.
func (c *Chain) rotateIfFullLocked() {
	if c.segmentBytes <= 0 {
		return
	}
	if err := c.openLocked(); err != nil {
		return // writeLocked reports it
	}
	if c.size < c.segmentBytes {
		return
	}
	if err := c.rotateLocked(); err != nil {
		log.Printf("receipts: %s stays in one file, could not rotate it into a segment: %v", c.path, err)
	}
}

// rotateLocked compresses the current file into the next segment and
// starts an empty current file. Called with c.mu held and the file open.
func (c *Chain) rotateLocked() error {
	// what the segment will hold must be on disk first: nothing is lost
	// if the copy or the truncation fails
	if err := c.f.Sync(); err != nil {
		return err
	}
	segs := segmentsOf(c.path)
	next := 1
	if len(segs) > 0 {
		next = segs[len(segs)-1].n + 1
	}
	dst := segmentName(c.path, next)
	if _, err := os.Stat(dst); err == nil {
		return fmt.Errorf("%s already exists", dst)
	}
	in, err := os.Open(c.path)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(c.path), ".segment-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	zw := gzip.NewWriter(tmp)
	if _, err := io.Copy(zw, in); err != nil {
		tmp.Close()
		return err
	}
	if err := zw.Close(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return err
	}
	syncDir(filepath.Dir(c.path)) // the segment's name must survive a crash too
	// The segment is in place: the current file starts over. It is closed
	// first, because Windows will not truncate a file still open for
	// writing. Should that fail, the segment is removed again, so the
	// current file stays the one copy of those receipts.
	err = c.f.Close()
	c.f = nil
	if err != nil {
		os.Remove(dst)
		return err
	}
	if err := os.Truncate(c.path, 0); err != nil {
		os.Remove(dst)
		return err
	}
	c.size = 0
	c.rotatedThrough = c.seq
	return nil
}

// repairInterruptedRotation finishes a rotation a crash cut short between
// the segment being written and the current file being emptied: the
// current file is then a copy of the newest segment, first line to last,
// and is emptied now. Any other current file is left alone.
func repairInterruptedRotation(path string) error {
	segs := segmentsOf(path)
	if len(segs) == 0 {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil || len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	newest := segs[len(segs)-1].name
	var first, last []byte
	n := 0
	if err := eachLineOf(newest, true, func(l []byte) error {
		if n == 0 {
			first = append([]byte(nil), l...)
		}
		last = append(last[:0], l...)
		n++
		return nil
	}); err != nil {
		return nil // the verifier will say what is wrong with the segment
	}
	firstCur := bytes.SplitN(bytes.TrimLeft(data, "\n"), []byte{'\n'}, 2)[0]
	if n == 0 || !bytes.Equal(firstCur, first) || !bytes.Equal(lastNonEmptyLine(data), last) {
		return nil
	}
	log.Printf("receipts: finishing a rotation into %s that was cut short", newest)
	return os.Truncate(path, 0)
}
