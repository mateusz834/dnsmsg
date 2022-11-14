package dnsmsg

import (
	"bytes"
	"strings"
	"testing"
)

func TestBuilderNameZeroValuePanic(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("builder.Name(BuilderName{}) didn't panic")
		}
	}()

	b := NewBuilder(nil)
	b.Name(&BuilderName{})
}

var (
	longDNSPrefix = strings.Repeat("verylongdomainlabel.", 20)
)

func longName(length int, suffix string) string {
	return longDNSPrefix[:length-len(suffix)] + suffix
}

var builderNameStringTests = []struct {
	name string

	expect []byte
	err    error
}{
	{name: "go.dev", expect: []byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0}},
	{name: "go.dev.", expect: []byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0}},
	{name: "www.go.dev", expect: []byte{3, 'w', 'w', 'w', 2, 'g', 'o', 3, 'd', 'e', 'v', 0}},
	{name: "www.go.dev.", expect: []byte{3, 'w', 'w', 'w', 2, 'g', 'o', 3, 'd', 'e', 'v', 0}},

	{name: "s\\.th.go.dev.", expect: []byte{4, 's', '.', 't', 'h', 2, 'g', 'o', 3, 'd', 'e', 'v', 0}},
	{name: "s\\\\th.go.dev.", expect: []byte{4, 's', '\\', 't', 'h', 2, 'g', 'o', 3, 'd', 'e', 'v', 0}},
	{name: "s\\th.go.dev.", expect: []byte{3, 's', 't', 'h', 2, 'g', 'o', 3, 'd', 'e', 'v', 0}},

	{name: "sth.go.dev\\", err: errInvalidDNSName},

	{name: "s\\000th.go.dev.", expect: []byte{4, 's', 0, 't', 'h', 2, 'g', 'o', 3, 'd', 'e', 'v', 0}},
	{name: "s\\128\\255h.go.dev.", expect: []byte{4, 's', 128, 255, 'h', 2, 'g', 'o', 3, 'd', 'e', 'v', 0}},
	{name: "go.dev\\010", expect: []byte{2, 'g', 'o', 4, 'd', 'e', 'v', 10, 0}},
	{name: "s\\256th.go.dev.", err: errInvalidDNSName},
	{name: "s\\0A0th.go.dev.", err: errInvalidDNSName},
	{name: "s\\00Ath.go.dev.", err: errInvalidDNSName},
	{name: "go.dev\\01", err: errInvalidDNSName},

	{name: "s\\T12h.go.dev.", expect: []byte{5, 's', 'T', '1', '2', 'h', 2, 'g', 'o', 3, 'd', 'e', 'v', 0}},

	{name: longName(253, ".go.dev")},
	{name: longName(254, ".go.dev"), err: errInvalidDNSName},
	{name: longName(254, ".go.dev.")},
	{name: longName(255, ".go.dev."), err: errInvalidDNSName},

	{name: strings.Repeat("a", 63) + ".go.dev.", expect: func() []byte {
		name := bytes.Repeat([]byte{'a'}, 63)
		name = append([]byte{63}, name...)
		return append(name, []byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0}...)
	}()},

	{name: strings.Repeat("a", 64) + ".go.dev.", err: errInvalidDNSName},
}

func TestBuilderNameString(t *testing.T) {
	for i, v := range builderNameStringTests {
		b := NewBuilder(make([]byte, 0, 256))
		n := NewStringName(v.name)
		err := b.Name(&n)
		if err != v.err {
			t.Errorf("%v: %#v: expected error: %v, got: %v", i, v.name, v.err, err)
			continue
		}

		if v.err != nil || v.expect == nil {
			continue
		}

		got := b.Finish()
		if !bytes.Equal(v.expect, got) {
			t.Errorf("%v: %#v:\n\texpected: %v\n\t     got: %v", i, v.name, v.expect, got)
		}
	}
}

func FuzzBuilderName(f *testing.F) {
	f.Fuzz(func(t *testing.T, name []byte, o uint8, ptr uint16) {
		defer func() {
			r := recover()
			if o == 0 {
				if !(r == "cannot use zero value of BuilderName" && o == 0) {
					panic(r)
				}
				return
			}

			if r != nil {
				panic(r)
			}
		}()

		t.Logf("%#v %v %v", string(name), o, ptr)

		var bn BuilderName

		switch o {
		case 0:
			bn = BuilderName{}
		case 1:
			bn = NewPtrName(ptr)
		case 2:
			bn = NewRootName()
		case 3:
			bn = NewRawName(name)
		case 4:
			bn = NewStringName(string(name))
		case 5:
			bn = NewBytesName(name)
		default:
			return
		}

		b := NewBuilder(make([]byte, 0, 256))
		b.Name(&bn)
	})
}

const builderBenchString = "imap.internal.go.dev"

var builderBenchRawName = [...]byte{4, 'i', 'm', 'a', 'p', 8, 'i', 'n', 't', 'e', 'r', 'n', 'a', 'l', 2, 'g', 'o', 3, 'd', 'e', 'v', 0}

/*
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
*/
