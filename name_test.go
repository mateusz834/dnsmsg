package dnsmsg

import "testing"

func TestBuilderNameZeroValuePanic(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("builder.Name(BuilderName{}) didn't panic")
		}
	}()

	b := NewBuilder(nil)
	b.Name(BuilderName{})
}

const builderBenchString = "imap.internal.go.dev"

var builderBenchRawName = [...]byte{4, 'i', 'm', 'a', 'p', 8, 'i', 'n', 't', 'e', 'r', 'n', 'a', 'l', 2, 'g', 'o', 3, 'd', 'e', 'v', 0}

func BenchmarkBuilderRawName(b *testing.B) {
	buf := make([]byte, 0, 256)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		name := builderBenchRawName
		b := NewBuilder(buf[:0:256])
		b.Name(NewRawName(name[:]))
		buf = b.Finish()
	}
}

func BenchmarkBuilderString(b *testing.B) {
	buf := make([]byte, 0, 256)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		name := builderBenchString
		b := NewBuilder(buf[:0:256])
		b.Name(NewStringName(name))
		buf = b.Finish()
	}
}

func BenchmarkBuilderBytes(b *testing.B) {
	buf := make([]byte, 0, 256)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		name := []byte(builderBenchString)
		b := NewBuilder(buf[:0:256])
		b.Name(NewBytesName(name))
		buf = b.Finish()
	}
}

func BenchmarkBuilderRawNameRoot(b *testing.B) {
	buf := make([]byte, 0, 256)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b := NewBuilder(buf[:0:256])
		b.Name(NewRawName([]byte{0}))
		buf = b.Finish()
	}
}

func BenchmarkBuilderRoot(b *testing.B) {
	buf := make([]byte, 0, 256)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b := NewBuilder(buf[:0:256])
		b.Name(NewRootName())
		buf = b.Finish()
	}
}

func BenchmarkBuilderRawNamePtr(b *testing.B) {
	buf := make([]byte, 0, 256)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b := NewBuilder(buf[:0:256])
		b.Name(NewRawName([]byte{0xC0, 128}))
		buf = b.Finish()
	}
}

func BenchmarkBuilderPtr(b *testing.B) {
	buf := make([]byte, 0, 256)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b := NewBuilder(buf[:0:256])
		b.Name(NewPtrName(128))
		buf = b.Finish()
	}
}
