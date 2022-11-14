package dnsmsg

import "testing"

func BenchmarkHashRawName(b *testing.B) {
	var hash uint8
	for i := 0; i < b.N; i++ {
		hash = hashRawName([]byte{1, hash, 2, 'g', 'o', 3, 'd', 'e', 'v', 0})
	}
}

func TestHashMap(t *testing.T) {
	msg := []byte{3, 'd', 'e', 'v', 0}
	hash := hashRawName(msg)

	h := hashMap{}
	bucket := &h.m[hash%10]
	bucket.entries[0].fullHash = hash
	bucket.entries[0].ptr = 0
	bucket.length++

	buf, ptr := h.compress(msg, []byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0})
	t.Log(buf, ptr)

	msg = append(msg, buf...)
	msg = appendUint16(msg, ptr|0xC000)

	buf, ptr = h.compress(msg, []byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0})
	t.Log(buf, ptr)
}

func BenchmarkHashMap(b *testing.B) {
	msg := make([]byte, 0, 128)

	for i := 0; i < b.N; i++ {
		h := hashMap{}
		msg = msg[:0:128]
		for i := 0; i < 10; i++ {
			buf, ptr := h.compress(msg, []byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0})
			msg = append(msg, buf...)
			msg = appendUint16(msg, ptr|0xC000)
		}
	}
}

func BenchmarkHashMap2(b *testing.B) {
	msg := make([]byte, 0, 128)

	for i := 0; i < b.N; i++ {
		b := NewBuilder(msg[:0:128])
		acm := CompressionNameBuilder{m: map[string]uint16{}}
		for i := 0; i < 10; i++ {
			name := acm.NewStringName("go.dev")
			b.Name(&name)
		}
	}
}
