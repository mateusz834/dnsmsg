package dnsmsg

import (
	"bytes"
	"encoding/binary"
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
	{name: "\x00", ok: true, diferentAsString: true},
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

	{name: label63, ok: true},
	{name: label64, ok: false},

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

		p := Parser{msg: packedName}
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
			buf = b.appendName(buf, 0, rawName, true)
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

		buf = b.appendName(buf, 0, raw1, true)
		for i := 0; i < 10; i++ {
			buf = b.appendName(buf, 0, raw1, true)
			buf = b.appendName(buf, 0, raw2, true)
			buf = b.appendName(buf, 0, raw3, true)
		}
	}
}

func BenchmarkBuilderAppendNameAllDifferentNamesCompressable(b *testing.B) {
	buf := make([]byte, headerLen, 512)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := buf
		b := nameBuilderState{}
		buf = b.appendName(buf, 0, mustNewRawNameValid("com"), true)
		buf = b.appendName(buf, 0, mustNewRawNameValid("example.com"), true)
		buf = b.appendName(buf, 0, mustNewRawNameValid("www.example.com"), true)
		buf = b.appendName(buf, 0, mustNewRawNameValid("dfd.www.example.com"), true)
		buf = b.appendName(buf, 0, mustNewRawNameValid("aa.dfd.www.example.com"), true)
		buf = b.appendName(buf, 0, mustNewRawNameValid("zz.aa.dfd.www.example.com"), true)
		buf = b.appendName(buf, 0, mustNewRawNameValid("cc.zz.aa.dfd.www.example.com"), true)
		buf = b.appendName(buf, 0, mustNewRawNameValid("aa.cc.zz.aa.dfd.www.example.com"), true)
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
			buf = b.appendName(buf, 0, mustNewRawNameValid(v), true)
		}
	}
}

func TestAppendName(t *testing.T) {
	cases := []struct {
		name   string
		build  func() []byte
		expect []byte
	}{
		{
			name: "one name",
			build: func() []byte {
				b := nameBuilderState{}
				return b.appendName(make([]byte, headerLen), 0, MustNewRawName("example.com."), true)
			},
			expect: append(
				make([]byte, headerLen),
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
			),
		},

		{
			name: "four same names",
			build: func() []byte {
				b := nameBuilderState{}
				buf := b.appendName(make([]byte, headerLen), 0, MustNewRawName("example.com."), true)
				buf = b.appendName(buf, 0, MustNewRawName("example.com."), true)
				buf = b.appendName(buf, 0, MustNewRawName("example.com."), true)
				return b.appendName(buf, 0, MustNewRawName("example.com."), true)
			},
			expect: append(
				make([]byte, headerLen),
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
				0xC0, 12,
				0xC0, 12,
				0xC0, 12,
			),
		},

		{
			name: "three compressable names",
			build: func() []byte {
				b := nameBuilderState{}
				buf := b.appendName(make([]byte, headerLen), 0, MustNewRawName("com."), true)
				buf = b.appendName(buf, 0, MustNewRawName("example.com."), true)
				return buf
				return b.appendName(buf, 0, MustNewRawName("www.example.com."), true)
			},
			expect: append(
				make([]byte, headerLen),
				3, 'c', 'o', 'm', 0,
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0xC0, 12,
				//3, 'w', 'w', 'w', 0xC0, 17,
			),
		},

		{
			name: "first root name followed by three compressable names",
			build: func() []byte {
				b := nameBuilderState{}
				buf := b.appendName(make([]byte, headerLen), 0, MustNewRawName("."), true)
				buf = b.appendName(buf, 0, MustNewRawName("com."), true)
				buf = b.appendName(buf, 0, MustNewRawName("example.com."), true)
				return b.appendName(buf, 0, MustNewRawName("www.example.com."), true)
			},
			expect: append(
				make([]byte, headerLen),
				0,
				3, 'c', 'o', 'm', 0,
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0xC0, 13,
				3, 'w', 'w', 'w', 0xC0, 18,
			),
		},
		{
			name: "compress=false",
			build: func() []byte {
				b := nameBuilderState{}
				buf := b.appendName(make([]byte, headerLen), 0, MustNewRawName("com."), true)
				buf = b.appendName(buf, 0, MustNewRawName("example.com."), false)
				return b.appendName(buf, 0, MustNewRawName("www.example.com."), true)
			},
			expect: append(
				make([]byte, headerLen),
				3, 'c', 'o', 'm', 0,
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
				3, 'w', 'w', 'w', 0xC0, 17,
			),
		},
	}

	for _, tt := range cases {
		buf := tt.build()
		if !bytes.Equal(buf, tt.expect) {
			t.Fatalf("%v:\nexpected: %v\ngot:      %v", tt.name, tt.expect, buf)
		}
	}
}

type testName struct {
	name     string
	compress bool
}

func randStringNames(rand []byte) []testName {
	var out []testName
	for len(rand) >= 5 {
		chars := int(binary.BigEndian.Uint16(rand[:4]))
		if chars > len(rand[5:]) {
			chars = len(rand[5:])
		}
		out = append(out, testName{string(rand[5 : 5+chars]), rand[4] < 127})
		rand = rand[5+chars:]
	}
	return out
}

func testAppendCompressed(buf []byte, compression map[string]uint16, name RawName, compress bool) []byte {
	if len(buf) < headerLen {
		panic("invalid use of testAppendCompressed")
	}

	first := len(buf) == headerLen

	// The nameBuilderState has an optimization (only for the first name),
	// that as a side effect allows compressing not only on label length boundry.
	defer func(bufStartLength int) {
		offset := 0
		if len(name) > 64 {
			offset = len(name) - 64
		}

		if first {
			for i := offset; i < len(name)-1; i++ {
				compression[string(name[i:])] = uint16(bufStartLength + i)
			}
		}
	}(len(buf))

	for i := 0; name[i] != 0; i += int(name[i]) + 1 {
		ptr, ok := compression[string(name[i:])]
		if compress && ok {
			buf = append(buf, name[:i]...)
			return appendUint16(buf, ptr|0xC000)
		}
		if !ok && len(buf)+i <= maxPtr {
			compression[string(name[i:])] = uint16(len(buf) + i)
		}
	}

	return append(buf, name...)
}

func FuzzAppendName(f *testing.F) {
	f.Fuzz(func(t *testing.T, rand []byte) {
		names := randStringNames(rand)
		for _, name := range names {
			n, err := NewRawName(name.name)
			if err != nil {
				return
			}
			encoding := ""
			for i := 0; i < len(n); i += int(n[i]) + 1 {
				if i != 0 {
					encoding += "\n"
				}
				encoding += fmt.Sprintf("%v %v", n[i], n[i+1:i+1+int(n[i])])
			}
			t.Logf("\nname %#v:\ncompress: %v\nencoding:\n%v", name.name, name.compress, encoding)
		}

		got := make([]byte, headerLen, 1024)
		b := nameBuilderState{}
		for _, name := range names {
			got = b.appendName(got, 0, MustNewRawName(name.name), name.compress)
		}

		expect := make([]byte, headerLen, 1024)
		compession := make(map[string]uint16)
		for _, name := range names {
			expect = testAppendCompressed(expect, compession, MustNewRawName(name.name), name.compress)
		}

		if !bytes.Equal(got, expect) {
			t.Fatalf("failed while appending names: %#v\n\tgot:      %v\n\texpected: %v", names, got, expect)
		}
	})
}
