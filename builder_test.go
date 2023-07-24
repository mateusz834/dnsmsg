package dnsmsg

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"net/netip"
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
			buf, _ = b.appendName(buf, math.MaxInt, 0, rawName, true)
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

		buf, _ = b.appendName(buf, math.MaxInt, 0, raw1, true)
		for i := 0; i < 10; i++ {
			buf, _ = b.appendName(buf, math.MaxInt, 0, raw1, true)
			buf, _ = b.appendName(buf, math.MaxInt, 0, raw2, true)
			buf, _ = b.appendName(buf, math.MaxInt, 0, raw3, true)
		}
	}
}

func BenchmarkBuilderAppendNameAllDifferentNamesCompressable(b *testing.B) {
	buf := make([]byte, headerLen, 512)
	b.ResetTimer()
	nb := nameBuilderState{}
	for i := 0; i < b.N; i++ {
		buf := buf
		nb.reset()
		buf, _ = nb.appendName(buf, math.MaxInt, 0, mustNewRawNameValid("com"), true)
		buf, _ = nb.appendName(buf, math.MaxInt, 0, mustNewRawNameValid("example.com"), true)
		buf, _ = nb.appendName(buf, math.MaxInt, 0, mustNewRawNameValid("www.example.com"), true)
		buf, _ = nb.appendName(buf, math.MaxInt, 0, mustNewRawNameValid("dfd.www.example.com"), true)
		buf, _ = nb.appendName(buf, math.MaxInt, 0, mustNewRawNameValid("aa.dfd.www.example.com"), true)
		buf, _ = nb.appendName(buf, math.MaxInt, 0, mustNewRawNameValid("zz.aa.dfd.www.example.com"), true)
		buf, _ = nb.appendName(buf, math.MaxInt, 0, mustNewRawNameValid("cc.zz.aa.dfd.www.example.com"), true)
		buf, _ = nb.appendName(buf, math.MaxInt, 0, mustNewRawNameValid("aa.cc.zz.aa.dfd.www.example.com"), true)
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
	builder := nameBuilderState{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		builder.reset()
		buf := buf
		for _, v := range names {
			buf, _ = builder.appendName(buf, math.MaxInt, 0, mustNewRawNameValid(v), true)
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
				buf, _ := b.appendName(make([]byte, headerLen), math.MaxInt, 0, MustNewRawName("example.com."), true)
				return buf
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
				buf, _ := b.appendName(make([]byte, headerLen), math.MaxInt, 0, MustNewRawName("example.com."), true)
				buf, _ = b.appendName(buf, math.MaxInt, 0, MustNewRawName("example.com."), true)
				buf, _ = b.appendName(buf, math.MaxInt, 0, MustNewRawName("example.com."), true)
				buf, _ = b.appendName(buf, math.MaxInt, 0, MustNewRawName("example.com."), true)
				return buf
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
				buf, _ := b.appendName(make([]byte, headerLen), math.MaxInt, 0, MustNewRawName("com."), true)
				buf, _ = b.appendName(buf, math.MaxInt, 0, MustNewRawName("example.com."), true)
				buf, _ = b.appendName(buf, math.MaxInt, 0, MustNewRawName("www.example.com."), true)
				return buf
			},
			expect: append(
				make([]byte, headerLen),
				3, 'c', 'o', 'm', 0,
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0xC0, 12,
				3, 'w', 'w', 'w', 0xC0, 17,
			),
		},

		{
			name: "first root name followed by three compressable names",
			build: func() []byte {
				b := nameBuilderState{}
				buf, _ := b.appendName(make([]byte, headerLen), math.MaxInt, 0, MustNewRawName("."), true)
				buf, _ = b.appendName(buf, math.MaxInt, 0, MustNewRawName("com."), true)
				buf, _ = b.appendName(buf, math.MaxInt, 0, MustNewRawName("example.com."), true)
				buf, _ = b.appendName(buf, math.MaxInt, 0, MustNewRawName("www.example.com."), true)
				return buf
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
				buf, _ := b.appendName(make([]byte, headerLen), math.MaxInt, 0, MustNewRawName("com."), true)
				buf, _ = b.appendName(buf, math.MaxInt, 0, MustNewRawName("example.com."), false)
				buf, _ = b.appendName(buf, math.MaxInt, 0, MustNewRawName("www.example.com."), true)
				return buf
			},
			expect: append(
				make([]byte, headerLen),
				3, 'c', 'o', 'm', 0,
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
				3, 'w', 'w', 'w', 0xC0, 17,
			),
		},
		{
			name: "maxBufSize on first name",
			build: func() []byte {
				b := nameBuilderState{}
				buf, err := b.appendName(make([]byte, headerLen), 30, 0, MustNewRawName("example.com."), true)
				if err != nil {
					// TODO: don't panic here.
					panic(err)
				}
				buf, err = b.appendName(buf, 30, 0, MustNewRawName("example.com."), true)
				if err != nil {
					panic(err)
				}
				buf, err = b.appendName(buf, 30, 0, MustNewRawName("example.com."), true)
				if err != nil {
					panic(err)
				}
				buf, err = b.appendName(buf, 30, 0, MustNewRawName("example.com."), true)
				if err != ErrTruncated {
					panic(err)
				}
				return buf
			},
			expect: append(
				make([]byte, headerLen),
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
				0xC0, 12,
				0xC0, 12,
			),
		},
		{
			name: "maxBufSize",
			build: func() []byte {
				b := nameBuilderState{}
				buf, err := b.appendName(make([]byte, headerLen), 30, 0, MustNewRawName("example.com."), true)
				if err != nil {
					// TODO: don't panic here.
					panic(err)
				}
				buf, err = b.appendName(buf, 30, 0, MustNewRawName("example.com."), true)
				if err != nil {
					panic(err)
				}
				buf, err = b.appendName(buf, 30, 0, MustNewRawName("www.example.com."), true)
				if err != ErrTruncated {
					panic(err)
				}
				buf, err = b.appendName(buf, 128, 0, MustNewRawName("www.example.com."), true)
				if err != nil {
					panic(err)
				}
				return buf
			},
			expect: append(
				make([]byte, headerLen),
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
				0xC0, 12,
				3, 'w', 'w', 'w', 0xC0, 12,
			),
		},
		{
			name: "maxBufSize entire not compressed second name",
			build: func() []byte {
				b := nameBuilderState{}
				buf, err := b.appendName(make([]byte, headerLen), 30, 0, MustNewRawName("example.com."), true)
				if err != nil {
					// TODO: don't panic here.
					panic(err)
				}
				n := MustNewRawName("example.net.")
				buf, err = b.appendName(buf, len(buf)+len(n)-1, 0, n, true)
				if err != ErrTruncated {
					panic(err)
				}
				buf, err = b.appendName(buf, 128, 0, MustNewRawName("www.example.net"), true)
				if err != nil {
					panic(err)
				}
				buf, err = b.appendName(buf, 128, 0, n, true)
				if err != nil {
					panic(err)
				}
				return buf
			},
			expect: append(
				make([]byte, headerLen),
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
				3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'n', 'e', 't', 0,
				0xC0, 29,
			),
		},
		{
			name: "first name, removeNamesFromCompressionMap",
			build: func() []byte {
				b := nameBuilderState{}
				buf, _ := b.appendName(make([]byte, headerLen), math.MaxInt, 0, MustNewRawName("com."), true)
				b.removeNamesFromCompressionMap(0, headerLen)
				buf, _ = b.appendName(buf[:headerLen], math.MaxInt, 0, MustNewRawName("com."), true)
				buf, _ = b.appendName(buf, math.MaxInt, 0, MustNewRawName("example.com."), false)
				buf, _ = b.appendName(buf, math.MaxInt, 0, MustNewRawName("www.example.com."), true)
				return buf
			},
			expect: append(
				make([]byte, headerLen),
				3, 'c', 'o', 'm', 0,
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
				3, 'w', 'w', 'w', 0xC0, 17,
			),
		},
		{
			name: "after first name, removeNamesFromCompressionMap",
			build: func() []byte {
				b := nameBuilderState{}
				buf, _ := b.appendName(make([]byte, headerLen), math.MaxInt, 0, MustNewRawName("com."), true)
				buf, _ = b.appendName(buf, math.MaxInt, 0, MustNewRawName("example.com."), false)
				offset := len(buf)
				buf, _ = b.appendName(buf, math.MaxInt, 0, MustNewRawName("www.example.com."), true)
				b.removeNamesFromCompressionMap(0, offset)
				buf = buf[:offset]
				buf, _ = b.appendName(buf, math.MaxInt, 0, MustNewRawName("www.example.com."), true)
				return buf
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
	name                 string
	incMaxBufLen         uint16
	removeLastNamesCount uint16
	compress             bool
}

func randStringNames(rand []byte) []testName {
	var out []testName
	for len(rand) >= 9 {
		nameCharCount := int(binary.BigEndian.Uint32(rand[5:9]))
		if nameCharCount > len(rand[9:]) {
			nameCharCount = len(rand[9:])
		}
		out = append(out, testName{
			name:                 string(rand[9 : 9+nameCharCount]),
			incMaxBufLen:         binary.BigEndian.Uint16(rand[0:2]),
			removeLastNamesCount: binary.BigEndian.Uint16(rand[2:4]),
			compress:             rand[5] < 127,
		})
		rand = rand[9+nameCharCount:]
	}
	return out
}

func testAppendCompressed(buf []byte, maxBufSize int, compression map[string]uint16, name RawName, compress bool) ([]byte, error) {
	if len(buf) < headerLen {
		panic("invalid use of testAppendCompressed")
	}

	compressFirstName := true

	// The nameBuilderState has an optimization (only for the first name),
	// that as a side effect allows compressing not only on label length boundry.
	defer func(bufStartLength int) {
		if compressFirstName && bufStartLength == headerLen {
			for i := 0; i < len(name)-1; i++ {
				compression[string(name[i:])] = uint16(bufStartLength + i)
			}
		}
	}(len(buf))

	for i := 0; name[i] != 0; i += int(name[i]) + 1 {
		ptr, ok := compression[string(name[i:])]
		if compress && ok {
			if len(buf)+i+2 > maxBufSize {
				for j := 0; j < i; j += int(name[j]) + 1 {
					delete(compression, string(name[j:]))
				}
				compressFirstName = false
				return buf, ErrTruncated
			}
			buf = append(buf, name[:i]...)
			return appendUint16(buf, ptr|0xC000), nil
		}
		if !ok && len(buf)+i <= maxPtr {
			compression[string(name[i:])] = uint16(len(buf) + i)
		}
	}

	if len(buf)+len(name) > maxBufSize {
		for i := 0; name[i] != 0; i += int(name[i]) + 1 {
			delete(compression, string(name[i:]))
		}
		compressFirstName = false
		return buf, ErrTruncated
	}
	return append(buf, name...), nil
}

func testRemoveLastlyCompressedName(msg []byte, compression map[string]uint16, headerStartOffset int, nameOffset int, name []byte) {
	if nameOffset == headerLen+headerStartOffset {
		for i := 0; i < len(name)-1; i++ {
			ptr, ok := compression[string(name[i:])]
			if ok && int(ptr) >= nameOffset {
				delete(compression, string(name[i:]))
			}
		}
		if len(compression) != 0 {
			panic("len(compression) != 0")
		}
	} else {
		for i := 0; name[i] != 0; i += int(name[i]) + 1 {
			ptr, ok := compression[string(name[i:])]
			if ok && int(ptr) >= nameOffset {
				delete(compression, string(name[i:]))
			}
		}
	}
}

const debugFuzz = false

func FuzzAppendName(f *testing.F) {
	f.Fuzz(func(t *testing.T, rand []byte) {
		names := randStringNames(rand)
		for _, name := range names {
			n, err := NewRawName(name.name)
			if err != nil {
				return
			}
			if debugFuzz {
				encoding := ""
				for i := 0; i < len(n); i += int(n[i]) + 1 {
					if i != 0 {
						encoding += "\n"
					}
					encoding += fmt.Sprintf("%v %v", n[i], n[i+1:i+1+int(n[i])])
				}
				t.Logf(
					"\nname %#v:\nincMaxBufLen: %v\nremoveLastNamesCount: %v\ncompress: %v\nencoding:\n%v",
					name.name, name.incMaxBufLen, name.removeLastNamesCount, name.compress, encoding,
				)
			}
		}

		var (
			expect      = make([]byte, headerLen, 1024)
			maxBufSize  = len(expect)
			compression = make(map[string]uint16)
		)

		var nameOffsets []int
		var appendedNames []string

		if debugFuzz {
			t.Logf("appending name to expect slice: %v", expect)
		}

		for i, name := range names {
			maxBufSize += int(name.incMaxBufLen)

			if debugFuzz {
				t.Logf("%v: name: %#v", i, name.name)
				t.Logf("%v: len(expect) = %v, maxBufSize: %v", i, len(expect), maxBufSize)
			}

			var err error
			offset := len(expect)
			expect, err = testAppendCompressed(expect, maxBufSize, compression, MustNewRawName(name.name), name.compress)

			if debugFuzz {
				t.Logf("%v: offset: %v, buf: %v, err: %v", i, offset, expect, err)
			}

			if err != nil && len(expect) != offset {
				t.Fatal("buf size changed")
			}

			for _, ptr := range compression {
				if int(ptr) >= len(expect) {
					t.Fatalf("stale entry found in compression map with ptr: %v", ptr)
				}
			}

			if len(expect) > maxBufSize {
				t.Fatalf("len(expect) = %v, len(expect) > maxBufSize", len(expect))
			}

			if err == nil {
				nameOffsets = append(nameOffsets, offset)
				appendedNames = append(appendedNames, name.name)
			}

			removeLastNamesCount := int(name.removeLastNamesCount)
			if removeLastNamesCount > len(nameOffsets) {
				removeLastNamesCount = len(nameOffsets)
			}

			if debugFuzz {
				t.Logf("%v: removeLastNamesCount: %v", i, removeLastNamesCount)
			}

			removeOffsets := nameOffsets[len(nameOffsets)-removeLastNamesCount:]
			removeNames := appendedNames[len(appendedNames)-removeLastNamesCount:]
			nameOffsets = nameOffsets[:len(nameOffsets)-removeLastNamesCount]
			appendedNames = appendedNames[:len(appendedNames)-removeLastNamesCount]

			for j := len(removeOffsets) - 1; j >= 0; j-- {
				offset := removeOffsets[j]
				name := removeNames[j]
				if debugFuzz {
					t.Logf("%v: removing last name: %#v at offset: %v", i, name, offset)
				}
				testRemoveLastlyCompressedName(expect, compression, 0, offset, MustNewRawName(name))
				expect = expect[:offset]
				if debugFuzz && j != 0 {
					t.Logf("%v: buf: %v", i, expect)
				}

				for _, ptr := range compression {
					if int(ptr) >= len(expect) {
						t.Fatalf("stale entry found in compression map with ptr: %v", ptr)
					}
				}
			}

			if debugFuzz {
				t.Logf("%v: buf: %v", i, expect)
				t.Log()
			}
		}

		p, _, _ := Parse(expect)
		for p.curOffset != len(p.msg) {
			expectName := appendedNames[0]
			appendedNames = appendedNames[1:]

			expectedNameOffset := nameOffsets[0]
			nameOffsets = nameOffsets[1:]

			name, n, err := p.unpackName(p.curOffset)
			if err != nil {
				t.Fatalf("failed to unpack name at offset: %v: %v", p.curOffset, err)
			}
			if !name.EqualName(MustNewName(expectName)) {
				t.Fatalf("name at offset: %v, is not euqal to: %#v", p.curOffset, expectName)
			}
			if expectedNameOffset != p.curOffset {
				t.Fatalf("name at offset: %v, was expected to be at: %v offset", p.curOffset, expectedNameOffset)
			}
			p.curOffset += int(n)
		}

		got := make([]byte, headerLen, 1024)
		b := nameBuilderState{}
		nameOffsets = nil
		appendedNames = nil
		maxBufSize = len(got)

		if debugFuzz {
			t.Logf("appending name to got slice: %v", got)
		}
		for i, name := range names {
			maxBufSize += int(name.incMaxBufLen)
			if debugFuzz {
				t.Logf("%v: name: %#v", i, name.name)
				t.Logf("%v: len(got) = %v, maxBufSize: %v", i, len(got), maxBufSize)
			}

			var err error
			offset := len(got)
			got, err = b.appendName(got, maxBufSize, 0, MustNewRawName(name.name), name.compress)
			if debugFuzz {
				t.Logf("%v: offset: %v, buf: %v, err: %v", i, offset, got, err)
			}

			if err != nil && len(got) != offset {
				t.Fatal("buf size changed")
			}

			if err == nil {
				nameOffsets = append(nameOffsets, offset)
				appendedNames = append(appendedNames, name.name)
			}

			removeLastNamesCount := int(name.removeLastNamesCount)
			if removeLastNamesCount > len(nameOffsets) {
				removeLastNamesCount = len(nameOffsets)
			}

			if debugFuzz {
				t.Logf("%v: removeLastNamesCount: %v", i, removeLastNamesCount)
			}

			removeOffsets := nameOffsets[len(nameOffsets)-removeLastNamesCount:]
			removeNames := appendedNames[len(appendedNames)-removeLastNamesCount:]
			nameOffsets = nameOffsets[:len(nameOffsets)-removeLastNamesCount]
			appendedNames = appendedNames[:len(appendedNames)-removeLastNamesCount]

			for j := len(removeOffsets) - 1; j >= 0; j-- {
				offset := removeOffsets[j]
				name := removeNames[j]

				if debugFuzz {
					t.Logf("%v: removing last name: %#v at offset: %v", i, name, offset)
				}
				b.removeNamesFromCompressionMap(0, offset)
				got = got[:offset]
				if debugFuzz && j != 0 {
					t.Logf("%v: buf: %v", i, got)
				}
			}

			if debugFuzz {
				t.Logf("%v: buf: %v", i, got)
				t.Log()
			}
		}

		if !bytes.Equal(got, expect) {
			t.Fatalf("failed while appending names: %#v\n\tgot:      %v\n\texpected: %v", names, got, expect)
		}
	})
}

func TestBuilder(t *testing.T) {
	id := uint16(34581)
	var f Flags
	f.SetRCode(RCodeSuccess)
	f.SetOpCode(OpCodeQuery)
	f.SetBit(BitRD, true)
	f.SetBit(BitRA, true)
	f.SetBit(BitAD, true)
	f.SetResponse()

	startLength := 128
	b := StartBuilder(make([]byte, startLength, 1024), id, f)
	err := b.Question(Question[RawName]{
		Name:  MustNewRawName("example.com"),
		Type:  TypeA,
		Class: ClassIN,
	})
	if err != nil {
		t.Fatalf("b.Question() unexpected error: %v", err)
	}

	rhdr := ResourceHeader[RawName]{
		Name:  MustNewRawName("example.com"),
		Class: ClassIN,
		TTL:   3600,
	}

	var (
		resourceA    = ResourceA{A: [4]byte{192, 0, 2, 1}}
		resourceAAAA = ResourceAAAA{AAAA: netip.MustParseAddr("2001:db8::1").As16()}
		resourceTXT  = ResourceTXT{
			TXT: [][]byte{
				bytes.Repeat([]byte("a"), 209),
				bytes.Repeat([]byte("b"), 105),
				bytes.Repeat([]byte("z"), 123),
			},
		}
		rawResourceTXT = RawResourceTXT{
			TXT: func() []byte {
				var raw []byte
				for _, str := range resourceTXT.TXT {
					raw = append(raw, uint8(len(str)))
					raw = append(raw, str...)
				}
				return raw
			}(),
		}
		resourceCNAME = ResourceCNAME[RawName]{CNAME: MustNewRawName("www.example.com")}
		resourceMX    = ResourceMX[RawName]{Pref: 54831, MX: MustNewRawName("smtp.example.com")}
	)

	for _, nextSection := range []func(){b.StartAnswers, b.StartAuthorities, b.StartAdditionals} {
		nextSection()

		rhdr.Type = TypeA
		rhdr.TTL = 32383739
		if err := b.ResourceA(rhdr, resourceA); err != nil {
			t.Fatalf("b.ResourceA() unexpected error: %v", err)
		}

		rhdr.Type = TypeAAAA
		rhdr.TTL = 3600
		if err := b.ResourceAAAA(rhdr, resourceAAAA); err != nil {
			t.Fatalf("b.ResourceAAAA() unexpected error: %v", err)
		}

		rhdr.Type = TypeTXT
		if err := b.ResourceTXT(rhdr, resourceTXT); err != nil {
			t.Fatalf("b.ResourceTXT() unexpected error: %v", err)
		}
		if err := b.RawResourceTXT(rhdr, rawResourceTXT); err != nil {
			t.Fatalf("b.RawResourceTXT() unexpected error: %v", err)
		}

		rhdr.Type = TypeCNAME
		if err := b.ResourceCNAME(rhdr, resourceCNAME); err != nil {
			t.Fatalf("b.ResourceCNAME() unexpected error: %v", err)
		}

		rhdr.Type = TypeMX
		if err := b.ResourceMX(rhdr, resourceMX); err != nil {
			t.Fatalf("b.ResourceMX() unexpected error: %v", err)
		}
	}

	msg := b.Bytes()

	if !bytes.Equal(msg[:startLength], make([]byte, startLength)) {
		t.Fatal("builder modified msg[:startLength]")
	}

	p, hdr, err := Parse(msg[startLength:])
	if err != nil {
		t.Fatalf("Parse(): unexpected error: %v", err)
	}

	expectHeader := Header{
		ID:      id,
		Flags:   f,
		QDCount: 1,
		ANCount: 6,
		NSCount: 6,
		ARCount: 6,
	}

	if hdr != expectHeader {
		t.Fatalf("Parse() unexpected header: %#v, want: %#v", hdr, expectHeader)
	}

	q, err := p.Question()
	if err != nil {
		t.Fatalf("p.Question() unexpected error: %v", err)
	}

	if !q.Name.EqualName(MustNewName("example.com")) {
		t.Errorf(`q.Name = %v, q.Name.EqualName(MustNewName("example.com") = false, want: true`, q.Name.String())
	}

	if q.Type != TypeA {
		t.Errorf(`q.Type = %v, want: %v`, q.Type, TypeA)
	}

	if q.Class != ClassIN {
		t.Errorf(`q.Class = %v, want: %v`, q.Class, ClassIN)
	}

	parseResourceHeader := func(curSection string, qType Type, class Class, ttl uint32) {
		rhdr, err := p.ResourceHeader()
		if err != nil {
			t.Fatalf("p.ResourceHeader() unexpected error: %v", err)
		}

		if !rhdr.Name.Equal(&q.Name) {
			t.Errorf("rhdr.Name = %v, rhdr.Name.Equal(&q.Name) = false, want: true", rhdr.Name.String())
		}

		if !rhdr.Name.EqualName(MustNewName("example.com")) {
			t.Errorf(`rhdr.Name = %v, rhdr.Name.Equal(MustNewName("example.com")) = false, want: true`, rhdr.Name.String())
		}

		if rhdr.Type != qType {
			t.Errorf(`rhdr.Type = %v, want: %v`, rhdr.Type, qType)
		}

		if rhdr.Class != class {
			t.Errorf(`rhdr.Class =  %v, want: %v`, rhdr.Class, class)
		}

		if rhdr.TTL != ttl {
			t.Errorf(`rhdr.TTL = %v, want: %v`, rhdr.TTL, ttl)
		}
	}

	sectionNames := []string{"Questions", "Answers", "Authorities", "Additionals"}
	for i, nextSection := range []func() error{p.StartAnswers, p.StartAuthorities, p.StartAdditionals} {
		curSectionName := sectionNames[i+1]
		if err := nextSection(); err != nil {
			t.Fatalf("%v section, p.Start%v(): unexpected error: %v", sectionNames[i], curSectionName, err)
		}

		parseResourceHeader(curSectionName, TypeA, ClassIN, 32383739)
		resA, err := p.ResourceA()
		if err != nil {
			t.Fatalf("%v section, p.ResourceA(): unexpected error: %v", curSectionName, err)
		}
		if resA != resourceA {
			t.Errorf("%v section, p.ResourceA() = %#v, want: %#v", curSectionName, resA, resourceA)
		}

		parseResourceHeader(curSectionName, TypeAAAA, ClassIN, 3600)
		resAAAA, err := p.ResourceAAAA()
		if err != nil {
			t.Fatalf("%v section, p.ResourceAAAA(): unexpected error: %v", curSectionName, err)
		}
		if resAAAA != resourceAAAA {
			t.Errorf("%v section, p.ResourceAAAA() =  %#v, want: %#v", curSectionName, resAAAA, resourceAAAA)
		}

		parseResourceHeader(curSectionName, TypeTXT, ClassIN, 3600)
		resRawTXT, err := p.RawResourceTXT()
		if err != nil {
			t.Fatalf("%v section, p.RawResourceTXT(): unexpected error: %v", curSectionName, err)
		}
		if !bytes.Equal(resRawTXT.TXT, rawResourceTXT.TXT) {
			t.Errorf("%v section, p.RawResourceTXT() = t %#v, want: %#v", curSectionName, resRawTXT, rawResourceTXT)
		}

		parseResourceHeader(curSectionName, TypeTXT, ClassIN, 3600)
		resTXT, err := p.RawResourceTXT()
		if err != nil {
			t.Fatalf("%v section, p.RawResourceTXT(): unexpected error: %v", curSectionName, err)
		}
		if !bytes.Equal(resTXT.TXT, rawResourceTXT.TXT) {
			t.Errorf("%v section, p.RawResourceTXT() = %#v, want: %#v", curSectionName, resTXT, resourceTXT)
		}

		parseResourceHeader(curSectionName, TypeCNAME, ClassIN, 3600)
		resCNAME, err := p.ResourceCNAME()
		if err != nil {
			t.Fatalf("%v section, p.ResourceCNAME(): unexpected error: %v", curSectionName, err)
		}
		if !resCNAME.CNAME.EqualName(MustNewName("www.example.com")) {
			t.Errorf("%v section, p.ResourceCNAME().CNAME = %#v, want: %#v", curSectionName, resCNAME.CNAME.String(), resourceCNAME.CNAME)
		}

		parseResourceHeader(curSectionName, TypeMX, ClassIN, 3600)
		resMX, err := p.ResourceMX()
		if err != nil {
			t.Fatalf("%v section, p.ResourceMX(): unexpected error: %v", curSectionName, err)
		}
		if resMX.Pref != resourceMX.Pref {
			t.Errorf("%v section, p.ResourceMX().Pref = %v, want: %v", curSectionName, resMX.Pref, resourceMX.Pref)
		}
		if !resMX.MX.EqualName(MustNewName("smtp.example.com")) {
			t.Errorf("%v section, p.ResourceMX().MX = %v, want: %v", curSectionName, resMX.MX.String(), resourceMX.MX)
		}
	}

	if err := p.End(); err != nil {
		t.Fatalf("p.End() unexpected error: %v", err)
	}
}

func TestBuilderRDBuilder(t *testing.T) {
	b := StartBuilder(make([]byte, 0, 512), 0, 0)
	b.StartAnswers()
	rdb, err := b.RDBuilder(ResourceHeader[RawName]{
		Name:   MustNewRawName("example.com"),
		Type:   54839,
		Class:  ClassIN,
		Length: 100,
	})
	if err != nil {
		t.Fatalf("b.RDBuilder() unexpected error: %v", err)
	}
	if err := rdb.Name(MustNewRawName("www.example.com"), true); err != nil {
		t.Fatalf("rb.Name() unexpected error: %v", err)
	}
	if err := rdb.Bytes([]byte{128, 238, 197}); err != nil {
		t.Fatalf("rb.Bytes() unexpected error: %v", err)
	}
	if err := rdb.Name(MustNewRawName("smtp.example.com"), false); err != nil {
		t.Fatalf("rb.Name() unexpected error: %v", err)
	}
	if err := rdb.Uint8(237); err != nil {
		t.Fatalf("rb.Uint8() unexpected error: %v", err)
	}
	if err := rdb.Uint16(23837); err != nil {
		t.Fatalf("rb.Uint16() unexpected error: %v", err)
	}
	if err := rdb.Uint32(3847323837); err != nil {
		t.Fatalf("rb.Uint32() unexpected error: %v", err)
	}
	if err := rdb.Uint64(3874898383473443); err != nil {
		t.Fatalf("rb.Uint64() unexpected error: %v", err)
	}

	if err := b.ResourceA(ResourceHeader[RawName]{
		Name:  MustNewRawName("example.com"),
		Class: ClassIN,
		Type:  TypeA,
	}, ResourceA{}); err != nil {
		t.Fatalf("b.ResourceA() unexpected error: %v", err)
	}

	expectPanic := func(name string, f func()) {
		defer func() {
			if recover() == nil {
				t.Fatalf("%v: didn't panic", name)
			}
		}()
		f()
	}
	expectPanic("rb.Length()", func() { rdb.Length() })
	expectPanic("rb.Bytes()", func() { rdb.Bytes([]byte{1}) })
	expectPanic("rb.Uint8()", func() { rdb.Uint8(1) })
	expectPanic("rb.Uint16()", func() { rdb.Uint16(1) })
	expectPanic("rb.Uint32()", func() { rdb.Uint32(1) })
	expectPanic("rb.Uint64()", func() { rdb.Uint64(1) })

	p, hdr, err := Parse(b.Bytes())
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}

	expect := Header{ANCount: 2}
	if hdr != expect {
		t.Errorf("Parse() unexpected header: %#v, want: %#v", hdr, expect)
	}

	if err := p.StartAnswers(); err != nil {
		t.Fatalf("p.StartAnswers() unexpected error: %v", err)
	}

	if _, err := p.ResourceHeader(); err != nil {
		t.Fatalf("p.ResourceHeader() unexpected error: %v", err)
	}

	rdp, err := p.RDParser()
	if err != nil {
		t.Fatalf("p.RDParser() unexpected error: %v", err)
	}

	name, err := rdp.Name()
	if err != nil {
		t.Fatalf("rdp.Name() unexpected error: %v", err)
	}

	if !name.EqualName(MustNewName("www.example.com")) {
		t.Errorf(`name = %v, name.EqualName(MustNewName("www.example.com")) = false, want: true`, name.String())
	}

	if !name.Compressed() {
		t.Errorf("name.Compressed() = false, want: true")
	}

	rawBytes, err := rdp.Bytes(3)
	if err != nil {
		t.Fatalf("rdp.Bytes() unexpected error: %v", err)
	}

	expectRaw := []byte{128, 238, 197}
	if !bytes.Equal(rawBytes, expectRaw) {
		t.Errorf("rdp.Bytes(3) = %v, want: %v", rawBytes, expectRaw)
	}

	name2, err := rdp.Name()
	if err != nil {
		t.Fatalf("rdp.Name() unexpected error: %v", err)
	}

	if !name2.EqualName(MustNewName("smtp.example.com")) {
		t.Errorf(`name2 = %v, name2.EqualName(MustNewName("smtp.example.com")) = false, want: true`, name2.String())
	}

	if name2.Compressed() {
		t.Errorf("name.Compressed() = true, want: false")
	}

	u8, err := rdp.Uint8()
	if err != nil {
		t.Fatalf("rdp.Uint8() unexpected error: %v", err)
	}
	if u8 != 237 {
		t.Errorf("rdp.Uint8() = %v, want: 237", u8)
	}

	u16, err := rdp.Uint16()
	if err != nil {
		t.Fatalf("rdp.Uint16() unexpected error: %v", err)
	}
	if u16 != 23837 {
		t.Errorf("rdp.Uint16() = %v, want: 23837", u16)
	}

	u32, err := rdp.Uint32()
	if err != nil {
		t.Fatalf("rdp.Uint32() unexpected error: %v", err)
	}
	if u32 != 3847323837 {
		t.Errorf("rdp.Uint32() = %v, want: 3847323837", u32)
	}

	u64, err := rdp.Uint64()
	if err != nil {
		t.Fatalf("rdp.Uint64() unexpected error: %v", err)
	}
	if u64 != 3874898383473443 {
		t.Errorf("rdp.Uint64() = %v, want: 3874898383473443", u64)
	}

	if err := rdp.End(); err != nil {
		t.Fatalf("rdp.End() unexpected error: %v", err)
	}

	if _, err := p.ResourceHeader(); err != nil {
		t.Fatalf("p.ResourceHeader() unexpected error: %v", err)
	}

	if _, err := p.ResourceA(); err != nil {
		t.Fatalf("p.ResourceA() unexpected error: %v", err)
	}

	if err := p.End(); err != nil {
		t.Fatalf("p.End() unexpected error: %v", err)
	}
}

func TestBuilderRDBuilderRDataOverflow(t *testing.T) {
	b := StartBuilder(make([]byte, 0, 128), 0, 0)
	b.StartAnswers()
	rdb, err := b.RDBuilder(ResourceHeader[RawName]{
		Name:   MustNewRawName("."),
		Type:   54839,
		Class:  ClassIN,
		Length: 100,
	})
	if err != nil {
		t.Fatalf("b.RDBuilder() unexpected error: %v", err)
	}

	rdb.Bytes(make([]byte, math.MaxUint16-6))
	before := b.Bytes()[12:]

	if err := rdb.Name(MustNewRawName("www.example.com"), true); err == nil {
		t.Fatal("rb.Name(): unexpected success")
	}
	if !bytes.Equal(before, b.Bytes()[12:]) {
		t.Fatal("message modified after rb.Name()")
	}

	if err := rdb.Bytes(make([]byte, 7)); err == nil {
		t.Fatal("rb.Name(): unexpected success")
	}
	if !bytes.Equal(before, b.Bytes()[12:]) {
		t.Fatal("message modified after rb.Bytes()")
	}

	rdb.Bytes(make([]byte, 5))
	before = b.Bytes()[12:]

	if err := rdb.Uint64(1); err == nil {
		t.Fatal("rb.Uint64(): unexpected success")
	}
	if !bytes.Equal(before, b.Bytes()[12:]) {
		t.Fatal("message modified after rb.Uint64()")
	}

	if err := rdb.Uint32(1); err == nil {
		t.Fatal("rb.Uint32(): unexpected success")
	}
	if !bytes.Equal(before, b.Bytes()[12:]) {
		t.Fatal("message modified after rb.Uint32()")
	}

	if err := rdb.Uint16(1); err == nil {
		t.Fatal("rb.Uint16(): unexpected success")
	}
	if !bytes.Equal(before, b.Bytes()[12:]) {
		t.Fatal("message modified after rb.Uint16()")
	}

	rdb.Bytes(make([]byte, 1))
	before = b.Bytes()[12:]

	if err := rdb.Uint8(1); err == nil {
		t.Fatal("rb.Uint8(): unexpected success")
	}
	if !bytes.Equal(before, b.Bytes()[12:]) {
		t.Fatal("message modified after rb.Uint8()")
	}
}
