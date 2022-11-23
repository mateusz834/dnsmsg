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
	{name: "", err: errInvalidDNSName},
	{name: ".", expect: []byte{0}},

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
		err := b.Name(NewStringName(v.name))
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

func TestBuilderNameBytes(t *testing.T) {
	for i, v := range builderNameStringTests {
		b := NewBuilder(make([]byte, 0, 256))
		err := b.Name(NewBytesName([]byte(v.name)))
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

func TestBuilderNameRealloc(t *testing.T) {
	b := NewBuilder(make([]byte, 0, 1))
	err := b.Name(NewStringName("go.dev."))
	if err != nil {
		t.Fatal(err)
	}

	expect := []byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0}
	got := b.Finish()
	if !bytes.Equal(expect, got) {
		t.Fatalf("expected %v, got %v", expect, got)
	}
}

func TestBuilderNameReuse(t *testing.T) {
	b := NewBuilder(make([]byte, 2, 256))
	name := NewStringName("go.dev")

	for i := 0; i < 3; i++ {
		if err := b.Name(name); err != nil {
			t.Fatal(err)
		}
	}

	expect := []byte{0, 0, 2, 'g', 'o', 3, 'd', 'e', 'v', 0, 0xC0, 2, 0xC0, 2}
	got := b.Finish()

	if !bytes.Equal(expect, got) {
		t.Fatalf("expected %v, got %v", expect, got)
	}
}

func TestBuilderNameCompression(t *testing.T) {
	b := NewBuilder(make([]byte, 2, 256))
	name := NewStringName("go.dev.")
	for i := 0; i < 2; i++ {
		if err := b.Name(name); err != nil {
			t.Fatal(err)
		}
	}

	name = NewStringName("www.go.dev.")
	for i := 0; i < 2; i++ {
		if err := b.Name(name); err != nil {
			t.Fatal(err)
		}
	}

	expect := []byte{0, 0, 2, 'g', 'o', 3, 'd', 'e', 'v', 0, 0xC0, 2, 3, 'w', 'w', 'w', 0xC0, 2, 0xC0, 12}
	got := b.Finish()

	if !bytes.Equal(expect, got) {
		t.Fatalf("expected:\n %v got:\n %v", expect, got)
	}
}

func BenchmarkSthh(b *testing.B) {
	buf := make([]byte, 0, 128)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b := NewBuilder(buf[:0:128])
		b.Name(NewStringName("test"))
		invalid := NewStringName("invalid")
		for i := 0; i < 10; i++ {
			b.Name(invalid)
		}
		buf = b.Finish()
	}
}
