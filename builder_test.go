package dnsmsg

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

var (
	escapes          = "\\.\\223\\.\\\\"
	escapesCharCount = 4
	label54          = escapes + strings.Repeat("a", 54-2*escapesCharCount) + escapes
	label63          = escapes + strings.Repeat("a", 63-2*escapesCharCount) + escapes
	label64          = escapes + strings.Repeat("a", 64-2*escapesCharCount) + escapes
)

var newNameTests = []struct {
	name             string
	ok               bool
	diferentAsString bool
}{
	{name: "", ok: false},
	{name: ".", ok: true},
	{name: "com.", ok: true},
	{name: "com", ok: true},

	{name: "go.dev", ok: true},
	{name: "go.dev.", ok: true},
	{name: "www.go.dev", ok: true},
	{name: "www.go.dev.", ok: true},

	{name: "www..go.dev", ok: false},
	{name: ".www.go.dev", ok: false},
	{name: "..www.go.dev", ok: false},
	{name: "www.go.dev..", ok: false},

	{name: "www.go.dev\\.", ok: true},
	{name: "www.go.dev\\..", ok: true},
	{name: "www.go.dev\\...", ok: false},
	{name: "www\\..go.dev", ok: true},
	{name: "www\\...go.dev", ok: false},

	{name: "\\\\www.go.dev.", ok: true},
	{name: "\\\\www.go.dev.", ok: true},
	{name: "www.go.dev\\\\\\.", ok: true},
	{name: "www.go.dev\\\\\\.", ok: true},
	{name: "\\ww\\ w.go.dev", ok: true, diferentAsString: true},
	{name: "ww\\w.go.dev", ok: true, diferentAsString: true},
	{name: "www.go.dev\\\\", ok: true},

	{name: "\\223www.go.dev", ok: true},
	{name: "\\000www.go.dev", ok: true},
	{name: "\\255www.go.dev", ok: true},

	{name: "\\256www.go.dev", ok: false},
	{name: "\\999www.go.dev", ok: false},
	{name: "\\12www.go.dev", ok: false},
	{name: "\\1www.go.dev", ok: false},
	{name: "www.go.dev\\223", ok: true},
	{name: "www.go.dev\\12", ok: false},
	{name: "www.go.dev\\1", ok: false},
	{name: "www.go.dev\\", ok: false},

	{name: label63 + ".go.dev", ok: true},
	{name: label64 + ".go.dev", ok: false},

	// 253B non-rooted name.
	{
		name: fmt.Sprintf("%[1]v.%[1]v.%[1]v.%v.go.dev", label63, label54),
		ok:   true,
	},

	// 254B rooted name.
	{
		name: fmt.Sprintf("%[1]v.%[1]v.%[1]v.%v.go.dev.", label63, label54),
		ok:   true,
	},

	// 254B non-rooted name.
	{
		name: fmt.Sprintf("%[1]v.%[1]v.%[1]v.%va.go.dev", label63, label54),
		ok:   false,
	},

	// 255B rooted name.
	{
		name: fmt.Sprintf("%[1]v.%[1]v.%[1]v.%va.go.dev.", label63, label54),
		ok:   false,
	},
}

func TestNewName(t *testing.T) {
	for _, v := range newNameTests {
		_, err := NewName(v.name)
		expectErr := errInvalidName
		if v.ok {
			expectErr = nil
		}
		if expectErr != err {
			t.Errorf("'%v' got error: %v, expected: %v", v.name, err, expectErr)
		}
	}
}

func TestAppendEscapedName(t *testing.T) {
	for _, v := range newNameTests {
		n, err := NewName(v.name)
		if err != nil {
			continue
		}

		packedName := appendEscapedName(nil, true, v.name)

		p, err := NewParser(packedName)
		if err != nil {
			continue
		}

		name := ParserName{m: &p, nameStart: 0}
		_, err = name.unpack()
		if err != nil {
			t.Errorf("'%v' failed while unpacking packed name: %v\n\traw: %v", v.name, err, packedName)
			continue
		}

		if !name.EqualName(n) {
			t.Errorf("'%v' ParserName is not equal to name\n\traw: %v", v.name, packedName)
			continue
		}

		if v.diferentAsString {
			continue
		}

		expectName := v.name
		dotAtEnd := expectName[len(expectName)-1] == '.'
		if !dotAtEnd || (len(expectName) > 2 && dotAtEnd && expectName[len(expectName)-2] == '\\') {
			expectName += "."
		}

		if name := name.String(); name != expectName {
			t.Errorf("'%v' got name: %v, expected: %v\n\traw: %v", v.name, name, expectName, packedName)
		}
	}
}

func TestAppendSearchName(t *testing.T) {
	n, err := NewSearchName(MustNewName("www"), MustNewName("go.dev"))

	if err != nil {
		t.Fatal(err)
	}

	name := appendName(nil, n)
	expectName := []byte{3, 'w', 'w', 'w', 2, 'g', 'o', 3, 'd', 'e', 'v', 0}
	if !bytes.Equal(name, expectName) {
		t.Fatalf("expected: %v got: %v", expectName, name)
	}
}

func BenchmarkIterator(b *testing.B) {
	name := MustNewName("google.com")
	search := []Name{MustNewName("com"), MustNewName("com"), MustNewName("internal.google.com"), MustNewName("internal.it.google.com")}
	for i := 0; i < b.N; i++ {
		s := NewSearchNameIterator(name, search, 1)
		for n, ok := s.Next(); ok; n, ok = s.Next() {
			_ = n
		}
	}
}

func mustNewRawNameValid(name string) RawName {
	return appendEscapedName(make([]byte, 0, maxEncodedNameLen), true, name)
}

func BenchmarkBuilderAppendNameSameName(b *testing.B) {
	buf := make([]byte, headerLen, 512)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := buf
		b := nameBuilderState{}
		rawName := mustNewRawNameValid("www.example.com")
		for i := 0; i < 31; i++ {
			buf = b.appendName(buf, rawName, true, true)
		}
	}
}

func BenchmarkBuilderAppendNameAllPointsToFirstName(b *testing.B) {
	buf := make([]byte, headerLen, 512)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := buf
		b := nameBuilderState{}

		raw1 := mustNewRawNameValid("www.example.com")
		raw2 := mustNewRawNameValid("example.com")
		raw3 := mustNewRawNameValid("com")

		buf = b.appendName(buf, raw1, true, true)
		for i := 0; i < 10; i++ {
			buf = b.appendName(buf, raw1, true, true)
			buf = b.appendName(buf, raw2, true, true)
			buf = b.appendName(buf, raw3, true, true)
		}
	}
}

func BenchmarkBuilderAppendNameAllDifferentNamesCompressable(b *testing.B) {
	buf := make([]byte, headerLen, 512)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := buf
		b := nameBuilderState{}
		buf = b.appendName(buf, mustNewRawNameValid("com"), true, true)
		buf = b.appendName(buf, mustNewRawNameValid("example.com"), true, true)
		buf = b.appendName(buf, mustNewRawNameValid("www.example.com"), true, true)
		buf = b.appendName(buf, mustNewRawNameValid("dfd.www.example.com"), true, true)
		buf = b.appendName(buf, mustNewRawNameValid("aa.dfd.www.example.com"), true, true)
		buf = b.appendName(buf, mustNewRawNameValid("zz.aa.dfd.www.example.com"), true, true)
		buf = b.appendName(buf, mustNewRawNameValid("cc.zz.aa.dfd.www.example.com"), true, true)
		buf = b.appendName(buf, mustNewRawNameValid("aa.cc.zz.aa.dfd.www.example.com"), true, true)
	}
}

func BenchmarkBuilderAppendNameAllDifferentNamesCompressable16Names(b *testing.B) {
	names := make([]string, 16)

	for i := range names {
		if i == 0 {
			names[i] = "com"
			continue
		}
		names[i] = "aaaa" + "." + names[i-1]
	}

	buf := make([]byte, headerLen, 512)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := buf
		b := nameBuilderState{}
		for _, v := range names {
			buf = b.appendName(buf, mustNewRawNameValid(v), true, true)
		}
	}
}
