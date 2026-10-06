// lp format replica — internal/identity/canon.go (documented
// cross-language canonical encoding; v1 is frozen so it's duplicated
// here rather than exported).
package t2harness

import "encoding/binary"

type lpb struct{ buf []byte }

func (b *lpb) str(s string) *lpb {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(s)))
	b.buf = append(b.buf, l[:]...)
	b.buf = append(b.buf, s...)
	return b
}
func (b *lpb) strs(ss []string) *lpb {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(ss)))
	b.buf = append(b.buf, l[:]...)
	for _, s := range ss {
		b.str(s)
	}
	return b
}
func (b *lpb) i64(v int64) *lpb {
	var l [8]byte
	binary.BigEndian.PutUint64(l[:], uint64(v))
	b.buf = append(b.buf, l[:]...)
	return b
}
func (b *lpb) u32(v uint32) *lpb {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], v)
	b.buf = append(b.buf, l[:]...)
	return b
}
