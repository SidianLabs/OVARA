package receipts

// Long runs: the chain is split into segments so it does not grow one file
// without end. When the current file reaches the segment size, it is
// compressed to <name>.000001.jsonl.gz (then .000002, ...) and a fresh
// current file continues the same chain: its first receipt's prev_hash is
// the hash of the last receipt in the segment before it. Nothing is ever
// deleted by Ovara; readers and the verifier walk every segment in order.
// If a person moves old segments away, the chain still verifies from the
// earliest one kept (VerifyResult.Partial says so).

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
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

// SetRotation sets the segment size (0 or less: never rotate).
func (c *Chain) SetRotation(maxBytes int64) {
	c.mu.Lock()
	c.segmentBytes = maxBytes
	c.mu.Unlock()
}

func segmentPattern(path string) *regexp.Regexp {
	base := strings.TrimSuffix(filepath.Base(path), ".jsonl")
	return regexp.MustCompile(`^` + regexp.QuoteMeta(base) + `\.(\d{6})\.jsonl\.gz$`)
}

// Segments returns the archived segment files of the chain at path, oldest
// first (not including the current file).
func Segments(path string) []string {
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		return nil
	}
	re := segmentPattern(path)
	type seg struct {
		n    int
		name string
	}
	var segs []seg
	for _, e := range entries {
		if m := re.FindStringSubmatch(e.Name()); m != nil {
			n, _ := strconv.Atoi(m[1])
			segs = append(segs, seg{n, filepath.Join(filepath.Dir(path), e.Name())})
		}
	}
	sort.Slice(segs, func(i, j int) bool { return segs[i].n < segs[j].n })
	out := make([]string, 0, len(segs))
	for _, s := range segs {
		out = append(out, s.name)
	}
	return out
}

func segmentName(path string, n int) string {
	base := strings.TrimSuffix(path, ".jsonl")
	return fmt.Sprintf("%s.%06d.jsonl.gz", base, n)
}

// ForEachLine calls fn with every receipt line of the chain at path, oldest
// first: the archived segments, then the current file. fn must not keep the
// slice.
func ForEachLine(path string, fn func(line []byte) error) error {
	for _, s := range Segments(path) {
		if err := eachLineOf(s, true, fn); err != nil {
			return err
		}
	}
	err := eachLineOf(path, false, fn)
	if os.IsNotExist(err) {
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
	return sc.Err()
}

// Count is the number of receipts in the whole chain at path.
func Count(path string) int {
	n := 0
	_ = ForEachLine(path, func([]byte) error { n++; return nil })
	return n
}

// Size is the bytes the chain takes on disk: the current file and every
// segment, and the number of segments.
func Size(path string) (total int64, segments int) {
	for _, s := range Segments(path) {
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

// rotateLocked compresses the current file into the next segment and starts
// an empty current file. Called with c.mu held, after a write.
func (c *Chain) rotateLocked() error {
	segs := Segments(c.path)
	next := 1
	if len(segs) > 0 {
		m := segmentPattern(c.path).FindStringSubmatch(filepath.Base(segs[len(segs)-1]))
		n, _ := strconv.Atoi(m[1])
		next = n + 1
	}
	dst := segmentName(c.path, next)
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
	// only once the segment is safely in place does the current file restart
	return os.Truncate(c.path, 0)
}
