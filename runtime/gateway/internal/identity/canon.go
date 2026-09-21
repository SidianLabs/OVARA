package identity

// Canonical signed-payload encoding for leases and delegation hops.
//
// Format: a sequence of fields, each length-prefixed —
//
//	lp(s)  = u32be(len(utf8(s))) || utf8(s)      — strings, always present
//	lpu64  = u64be(v)                            — unix timestamps, ints
//	lparr  = u32be(count) || lp(item)*           — string arrays
//
// Properties that the old pipe/%v format lacked:
//   - field boundaries unambiguous ("x|y" in one field can't collide
//     with ("x","y") across two)
//   - arrays unambiguous (["a b"] != ["a","b"] — different byte counts)
//   - deterministic across languages: byte counts and big-endian ints,
//     no formatting quirks (Go %v, JSON escaping) to replicate.
//
// Every security-relevant field is inside the signed bytes; a signature
// identifies exactly one semantic object.
//
// The same canonical format is implemented by the Python SDK
// (ovara_sdk.canon) — cross-language vectors live in
// delegation_vectors_test.go / sdk/python.

import "encoding/binary"

// lpBuilder accumulates a length-prefixed canonical payload.
type lpBuilder struct {
	buf []byte
}

func (b *lpBuilder) str(s string) *lpBuilder {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(s)))
	b.buf = append(b.buf, l[:]...)
	b.buf = append(b.buf, s...)
	return b
}

func (b *lpBuilder) strs(ss []string) *lpBuilder {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(ss)))
	b.buf = append(b.buf, l[:]...)
	for _, s := range ss {
		b.str(s)
	}
	return b
}

func (b *lpBuilder) i64(v int64) *lpBuilder {
	var l [8]byte
	binary.BigEndian.PutUint64(l[:], uint64(v))
	b.buf = append(b.buf, l[:]...)
	return b
}

func (b *lpBuilder) u32(v uint32) *lpBuilder {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], v)
	b.buf = append(b.buf, l[:]...)
	return b
}
