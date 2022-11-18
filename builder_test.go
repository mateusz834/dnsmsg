package dnsmsg

import "testing"

const builderBenchString = "imap.internal.go.dev"

var builderBenchRawName = [...]byte{4, 'i', 'm', 'a', 'p', 8, 'i', 'n', 't', 'e', 'r', 'n', 'a', 'l', 2, 'g', 'o', 3, 'd', 'e', 'v', 0}

func TestCmpr(t *testing.T) {
	b := NewBuilder([]byte{1, 2, 3})

	r := NewRawName([]byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0})
	b.Name(r)

	r = NewRawName([]byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0})
	b.Name(r)

	t.Log(b.buf)
}

func BenchmarkCmprMakeQueryString(b *testing.B) {
	buf := make([]byte, 0, 256)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf, _ = MakeQuery(buf[:0:256], 11, 11, Question[*BuilderName]{
			Name:  NewStringName(builderBenchString),
			Type:  TypeA,
			Class: ClassIN,
		})
	}
}

func BenchmarkCmpr10SameNames(b *testing.B) {
	buf := make([]byte, 0, 256)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b := NewBuilder(buf[:0:256])
		r := NewRawName(builderBenchRawName[:])

		for j := 0; j < 10; j++ {
			b.Name(r)
		}
		buf = b.Finish()
	}
}

func BenchmarkCmpr10DiffrentNames(b *testing.B) {
	buf := make([]byte, 0, 128)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b := NewBuilder(buf[:0:128])

		r := NewRawName([]byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0})
		b.Name(r)

		for j := 0; j < 9; j++ {
			r := NewRawName([]byte{1, byte(j), 2, 'g', 'o', 3, 'd', 'e', 'v', 0})
			b.Name(r)
		}

		buf = b.Finish()
	}
}

/*
func BenchmarkCmprManualPtrName10SameNames(b *testing.B) {
	buf := make([]byte, 0, 128)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b := NewBuilder(buf[:0:128])

		r := NewRawName([]byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0})
		b.Name(&r)

		for j := 0; j < 9; j++ {
			n := NewPtrName(r.MsgOffset())
			b.Name(&n)
		}

		buf = b.Finish()
	}
}

func BenchmarkCmprManualPtrTo10SameNames(b *testing.B) {
	buf := make([]byte, 0, 128)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b := NewBuilder(buf[:0:128])

		r := NewRawName([]byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0})
		b.Name(&r)

		for j := 0; j < 9; j++ {
			n := NewRawNamePtrTo(nil, &r, 0)
			b.Name(&n)
		}

		buf = b.Finish()
	}
}

func BenchmarkCmprManualPtrTo210SameNames(b *testing.B) {
	buf := make([]byte, 0, 128)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b := NewBuilder(buf[:0:128])

		r := NewRawName([]byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0})
		b.Name2(&r)

		for j := 0; j < 9; j++ {
			n := NewRawNameWithPtrTo(nil, &r)
			b.Name2(&n)
		}

		buf = b.Finish()
	}
}
*/
