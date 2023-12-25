package dnsmsg

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"net/netip"
	"reflect"
	"testing"
)

func BenchmarkBuilderAppendNameSameName(b *testing.B) {
	buf := make([]byte, headerLen, 512)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := buf
		b := nameBuilderState{}
		rawName := MustParseName("www.example.com")
		for i := 0; i < 31; i++ {
			buf, _ = b.appendName(buf, math.MaxInt, 0, rawName.asSlice(), true)
		}
	}
}

func BenchmarkBuilderAppendNameAllPointsToFirstName(b *testing.B) {
	buf := make([]byte, headerLen, 512)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := buf
		b := nameBuilderState{}

		raw1 := MustParseName("www.example.com")
		raw2 := MustParseName("example.com")
		raw3 := MustParseName("com")

		buf, _ = b.appendName(buf, math.MaxInt, 0, raw1.asSlice(), true)
		for i := 0; i < 10; i++ {
			buf, _ = b.appendName(buf, math.MaxInt, 0, raw1.asSlice(), true)
			buf, _ = b.appendName(buf, math.MaxInt, 0, raw2.asSlice(), true)
			buf, _ = b.appendName(buf, math.MaxInt, 0, raw3.asSlice(), true)
		}
	}
}

func BenchmarkBuilderAppendNameAllDifferentNamesCompressable(b *testing.B) {
	buf := make([]byte, headerLen, 512)
	b.ResetTimer()
	nb := nameBuilderState{}
	for i := 0; i < b.N; i++ {
		names := []Name{
			MustParseName("com"),
			MustParseName("example.com"),
			MustParseName("www.example.com"),
			MustParseName("dfd.www.example.com"),
			MustParseName("aa.dfd.www.example.com"),
			MustParseName("zz.aa.dfd.www.example.com"),
			MustParseName("cc.zz.aa.dfd.www.example.com"),
			MustParseName("aa.cc.zz.aa.dfd.www.example.com"),
		}
		buf := buf
		nb.reset()
		buf, _ = nb.appendName(buf, math.MaxInt, 0, names[0].asSlice(), true)
		buf, _ = nb.appendName(buf, math.MaxInt, 0, names[1].asSlice(), true)
		buf, _ = nb.appendName(buf, math.MaxInt, 0, names[2].asSlice(), true)
		buf, _ = nb.appendName(buf, math.MaxInt, 0, names[3].asSlice(), true)
		buf, _ = nb.appendName(buf, math.MaxInt, 0, names[4].asSlice(), true)
		buf, _ = nb.appendName(buf, math.MaxInt, 0, names[5].asSlice(), true)
		buf, _ = nb.appendName(buf, math.MaxInt, 0, names[6].asSlice(), true)
		buf, _ = nb.appendName(buf, math.MaxInt, 0, names[7].asSlice(), true)
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
			n := MustParseName(v)
			buf, _ = builder.appendName(buf, math.MaxInt, 0, n.asSlice(), true)
		}
	}
}

func nameAsSlice(s string) []byte {
	n := MustParseName(s)
	return n.asSlice()
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
				buf, _ := b.appendName(make([]byte, headerLen), math.MaxInt, 0, nameAsSlice("example.com."), true)
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
				buf, _ := b.appendName(make([]byte, headerLen), math.MaxInt, 0, nameAsSlice("example.com."), true)
				buf, _ = b.appendName(buf, math.MaxInt, 0, nameAsSlice("example.com."), true)
				buf, _ = b.appendName(buf, math.MaxInt, 0, nameAsSlice("example.com."), true)
				buf, _ = b.appendName(buf, math.MaxInt, 0, nameAsSlice("example.com."), true)
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
				buf, _ := b.appendName(make([]byte, headerLen), math.MaxInt, 0, nameAsSlice("com."), true)
				buf, _ = b.appendName(buf, math.MaxInt, 0, nameAsSlice("example.com."), true)
				buf, _ = b.appendName(buf, math.MaxInt, 0, nameAsSlice("www.example.com."), true)
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
				buf, _ := b.appendName(make([]byte, headerLen), math.MaxInt, 0, nameAsSlice("."), true)
				buf, _ = b.appendName(buf, math.MaxInt, 0, nameAsSlice("com."), true)
				buf, _ = b.appendName(buf, math.MaxInt, 0, nameAsSlice("example.com."), true)
				buf, _ = b.appendName(buf, math.MaxInt, 0, nameAsSlice("www.example.com."), true)
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
				buf, _ := b.appendName(make([]byte, headerLen), math.MaxInt, 0, nameAsSlice("com."), true)
				buf, _ = b.appendName(buf, math.MaxInt, 0, nameAsSlice("example.com."), false)
				buf, _ = b.appendName(buf, math.MaxInt, 0, nameAsSlice("www.example.com."), true)
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
				buf, err := b.appendName(make([]byte, headerLen), 30, 0, nameAsSlice("example.com."), true)
				if err != nil {
					// TODO: don't panic here.
					panic(err)
				}
				buf, err = b.appendName(buf, 30, 0, nameAsSlice("example.com."), true)
				if err != nil {
					panic(err)
				}
				buf, err = b.appendName(buf, 30, 0, nameAsSlice("example.com."), true)
				if err != nil {
					panic(err)
				}
				buf, err = b.appendName(buf, 30, 0, nameAsSlice("example.com."), true)
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
				buf, err := b.appendName(make([]byte, headerLen), 30, 0, nameAsSlice("example.com."), true)
				if err != nil {
					// TODO: don't panic here.
					panic(err)
				}
				buf, err = b.appendName(buf, 30, 0, nameAsSlice("example.com."), true)
				if err != nil {
					panic(err)
				}
				buf, err = b.appendName(buf, 30, 0, nameAsSlice("www.example.com."), true)
				if err != ErrTruncated {
					panic(err)
				}
				buf, err = b.appendName(buf, 128, 0, nameAsSlice("www.example.com."), true)
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
				buf, err := b.appendName(make([]byte, headerLen), 30, 0, nameAsSlice("example.com."), true)
				if err != nil {
					// TODO: don't panic here.
					panic(err)
				}
				n := nameAsSlice("example.net.")
				buf, err = b.appendName(buf, len(buf)+len(n)-1, 0, n, true)
				if err != ErrTruncated {
					panic(err)
				}
				buf, err = b.appendName(buf, 128, 0, nameAsSlice("www.example.net"), true)
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
				buf, _ := b.appendName(make([]byte, headerLen), math.MaxInt, 0, nameAsSlice("com."), true)
				b.removeNamesFromCompressionMap(0, headerLen)
				buf, _ = b.appendName(buf[:headerLen], math.MaxInt, 0, nameAsSlice("com."), true)
				buf, _ = b.appendName(buf, math.MaxInt, 0, nameAsSlice("example.com."), false)
				buf, _ = b.appendName(buf, math.MaxInt, 0, nameAsSlice("www.example.com."), true)
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
			name: "multiple names, removeNamesFromCompressionMap, with fake name",
			build: func() []byte {
				b := nameBuilderState{}
				buf, _ := b.appendName(make([]byte, headerLen), math.MaxInt, 0, nameAsSlice("smtp.example.net."), true)
				buf, _ = b.appendName(buf, math.MaxInt, 0, nameAsSlice("www.example.com."), true)
				buf, _ = b.appendName(buf, math.MaxInt, 0, nameAsSlice("www.example.com."), true)
				b.removeNamesFromCompressionMap(0, headerLen)
				buf, _ = b.appendName(buf[:headerLen], math.MaxInt, 0, nameAsSlice("smtp.example.net."), true)
				buf = append(buf, 3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0)
				buf, _ = b.appendName(buf, math.MaxInt, 0, nameAsSlice("www.example.com."), true)
				return buf
			},
			expect: append(
				make([]byte, headerLen),
				4, 's', 'm', 't', 'p', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'n', 'e', 't', 0,
				3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
				3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
			),
		},
		{
			name: "after first name, removeNamesFromCompressionMap",
			build: func() []byte {
				b := nameBuilderState{}
				buf, _ := b.appendName(make([]byte, headerLen), math.MaxInt, 0, nameAsSlice("com."), true)
				buf, _ = b.appendName(buf, math.MaxInt, 0, nameAsSlice("example.com."), false)
				offset := len(buf)
				buf, _ = b.appendName(buf, math.MaxInt, 0, nameAsSlice("www.example.com."), true)
				b.removeNamesFromCompressionMap(0, offset)
				buf = buf[:offset]
				buf, _ = b.appendName(buf, math.MaxInt, 0, nameAsSlice("www.example.com."), true)
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
			name: "removeNamesFromCompressionMap with headerStartOffset",
			build: func() []byte {
				b := nameBuilderState{}
				headerStartOffset := 4
				buf := make([]byte, headerStartOffset+headerLen)
				buf, _ = b.appendName(buf, math.MaxInt, headerStartOffset, nameAsSlice("com."), true)
				buf, _ = b.appendName(buf, math.MaxInt, headerStartOffset, nameAsSlice("example.com."), false)
				offset := len(buf)
				buf, _ = b.appendName(buf, math.MaxInt, headerStartOffset, nameAsSlice("w.example.com."), true)
				b.removeNamesFromCompressionMap(headerStartOffset, offset)
				buf = buf[:offset]
				buf = append(buf, 1, 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0)
				buf, _ = b.appendName(buf, math.MaxInt, headerStartOffset, nameAsSlice("w.example.com."), true)
				return buf
			},
			expect: append(
				make([]byte, 4+headerLen),
				3, 'c', 'o', 'm', 0,
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
				1, 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
				1, 'w', 0xC0, 17,
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

func testAppendCompressed(buf []byte, headerStartOffset, maxBufSize int, compression map[string]uint16, name []byte, compress bool) ([]byte, error) {
	if len(buf) < headerLen {
		panic("invalid use of testAppendCompressed")
	}

	compressFirstName := true

	// The nameBuilderState has an optimization (only for the first name),
	// that as a side effect allows compressing not only on label length boundry.
	defer func(bufStartLength int) {
		if compressFirstName && bufStartLength-headerStartOffset == headerLen {
			for i := 0; i < len(name)-1; i++ {
				compression[string(name[i:])] = uint16(bufStartLength + i - headerStartOffset)
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
		if !ok && (len(buf)+i-headerStartOffset) <= maxPtr {
			compression[string(name[i:])] = uint16(len(buf) + i - headerStartOffset)
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
	nameOffset -= headerStartOffset
	if nameOffset == headerLen {
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

func FuzzAppendName(f *testing.F) {
	f.Fuzz(func(t *testing.T, rand []byte) {
		type testName struct {
			name                 string
			incMaxBufLen         uint16
			removeLastNamesCount uint16
			compress             bool
		}

		r := fuzzRand{t, rand}
		var names []testName
		for r.bool() {
			names = append(names, testName{
				name:                 string(r.arbitraryAmountOfBytes()),
				incMaxBufLen:         r.uint16(),
				removeLastNamesCount: r.uint16(),
				compress:             r.bool(),
			})
		}

		headerStartOffset := int(r.uint16())

		for _, name := range names {
			nn, err := ParseName(name.name)
			if err != nil {
				return
			}
			n := nn.asSlice()
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

		if debugFuzz {
			t.Logf("headerStartOffset: %v", headerStartOffset)
		}

		var (
			expect      = make([]byte, headerStartOffset+headerLen, headerStartOffset+1024)
			maxBufSize  = len(expect)
			compression = make(map[string]uint16)
		)

		var nameOffsets []int
		var appendedNames []string

		if debugFuzz {
			t.Logf("appending name to expect slice, len(expect) = %v", len(expect))
		}

		for i, name := range names {
			maxBufSize += int(name.incMaxBufLen)

			if debugFuzz {
				t.Logf("%v: name: %#v", i, name.name)
				t.Logf("%v: len(expect) = %v, maxBufSize: %v", i, len(expect), maxBufSize)
			}

			var err error
			offset := len(expect)
			expect, err = testAppendCompressed(expect, headerStartOffset, maxBufSize, compression, nameAsSlice(name.name), name.compress)

			if debugFuzz {
				t.Logf("%v: offset: %v, buf[headerStartOffset:]: %v, err: %v", i, offset, expect[headerStartOffset:], err)
			}

			if err != nil && len(expect) != offset {
				t.Fatal("buf size changed")
			}

			for _, ptr := range compression {
				if int(ptr) >= len(expect)-headerStartOffset {
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
				testRemoveLastlyCompressedName(expect, compression, headerStartOffset, offset, nameAsSlice(name))
				expect = expect[:offset]
				if debugFuzz && j != 0 {
					t.Logf("%v: buf[headerStartOffset:]: %v", i, expect[headerStartOffset:])
				}

				for _, ptr := range compression {
					if int(ptr) >= len(expect) {
						t.Fatalf("stale entry found in compression map with ptr: %v", ptr)
					}
				}
			}

			if debugFuzz {
				t.Logf("%v: buf[headerStartOffset:]: %v", i, expect[headerStartOffset:])
				t.Log()
			}
		}

		p, _, _ := Parse(expect[headerStartOffset:])
		for p.curOffset != len(p.msg) {
			expectName := appendedNames[0]
			appendedNames = appendedNames[1:]

			expectedNameOffset := nameOffsets[0] - headerStartOffset
			nameOffsets = nameOffsets[1:]

			var name Name
			offset, err := name.unpack(p.msg, p.curOffset)
			if err != nil {
				t.Fatalf("failed to unpack name at offset: %v: %v", p.curOffset, err)
			}
			expect := MustParseName(expectName)
			if !bytes.Equal(name.asSlice(), expect.asSlice()) {
				t.Fatalf("name at offset: %v, is not euqal to: %#v", p.curOffset, expectName)
			}
			if expectedNameOffset != p.curOffset {
				t.Fatalf("name at offset: %v, was expected to be at: %v offset", p.curOffset, expectedNameOffset)
			}
			p.curOffset += int(offset)
		}

		got := make([]byte, headerStartOffset+headerLen, headerStartOffset+1024)
		b := nameBuilderState{}
		nameOffsets = nil
		appendedNames = nil
		maxBufSize = len(got)

		if debugFuzz {
			t.Logf("appending name to got slice, len(got) = %v", len(got))
		}
		for i, name := range names {
			maxBufSize += int(name.incMaxBufLen)
			if debugFuzz {
				t.Logf("%v: name: %#v", i, name.name)
				t.Logf("%v: len(got) = %v, maxBufSize: %v", i, len(got), maxBufSize)
			}

			var err error
			offset := len(got)
			got, err = b.appendName(got, maxBufSize, headerStartOffset, nameAsSlice(name.name), name.compress)
			if debugFuzz {
				t.Logf("%v: offset: %v, buf[headerStartOffset:]: %v, err: %v", i, offset, got[headerStartOffset:], err)
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

			if len(nameOffsets) > 0 && removeLastNamesCount > 0 {
				removeOffset := nameOffsets[len(nameOffsets)-removeLastNamesCount]
				removeNames := appendedNames[len(appendedNames)-removeLastNamesCount:]
				nameOffsets = nameOffsets[:len(nameOffsets)-removeLastNamesCount]
				appendedNames = appendedNames[:len(appendedNames)-removeLastNamesCount]

				if debugFuzz {
					t.Logf("removing names: %#v at starting offset: %v", removeNames, removeOffset)
				}

				b.removeNamesFromCompressionMap(headerStartOffset, removeOffset)
				got = got[:removeOffset]
			}

			if debugFuzz {
				t.Logf("%v: buf[headerStartOffset:]: %v", i, got[headerStartOffset:])
				t.Log()
			}
		}

		if !bytes.Equal(got, expect) {
			t.Fatalf(
				"failed while appending names: %#v\n\tgot[headerStartOffset:]:      %v\n\texpected[headerStartOffset:]: %v",
				names, got[headerStartOffset:], expect[headerStartOffset:],
			)
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

	expectHeader := Header{
		ID:    id,
		Flags: f,
	}

	startLength := 128
	b := StartBuilder(make([]byte, startLength, 1024), id, f)

	testAfterAppend := func(name string) {
		switch name {
		case "Questions":
			expectHeader.QDCount++
		case "Answers":
			expectHeader.ANCount++
		case "Authorities":
			expectHeader.NSCount++
		case "Additionals":
			expectHeader.ARCount++
		default:
			panic("unknown section: " + name)
		}

		if hdr := b.Header(); hdr != expectHeader {
			t.Fatalf("%v section, unexpected header: %#v, want: %#v", name, hdr, expectHeader)
		}

		length := b.Length()
		msg := b.Bytes()
		if len(msg)-startLength != length {
			t.Fatalf("%v section, b.Length() = %v, want: %v", name, length, len(msg)-startLength)
		}

		_, hdr, err := Parse(msg[startLength:])
		if err != nil {
			t.Fatalf("%v, section, Parse(msg) returned error: %v", name, err)
		}

		if hdr != expectHeader {
			t.Fatalf("%v section, Parse(msg) unexpected header: %#v, want: %#v", name, hdr, expectHeader)
		}

		expectHeader.ID += uint16(b.Length())
		b.SetID(expectHeader.ID)
		expectHeader.Flags += Flags(len(msg))
		b.SetFlags(expectHeader.Flags)
	}

	err := b.Question(Question{
		Name:  MustParseName("example.com"),
		Type:  TypeA,
		Class: ClassIN,
	})
	if err != nil {
		t.Fatalf("b.Question() unexpected error: %v", err)
	}

	testAfterAppend("Questions")

	rhdr := ResourceHeader{
		Name:  MustParseName("example.com"),
		Class: ClassIN,
		TTL:   3600,
	}

	var (
		resourceA    = ResourceA{A: [4]byte{192, 0, 2, 1}}
		resourceAAAA = ResourceAAAA{AAAA: netip.MustParseAddr("2001:db8::1").As16()}
		resourceNS   = ResourceNS{NS: MustParseName("ns1.example.com")}
		resourceSOA  = ResourceSOA{
			NS:      MustParseName("ns1.example.com"),
			Mbox:    MustParseName("admin.example.com"),
			Serial:  2022010199,
			Refresh: 3948793,
			Retry:   34383744,
			Expire:  1223999999,
			Minimum: 123456789,
		}
		resourcePTR = ResourcePTR{PTR: MustParseName("1.2.0.192.in-addr.arpa")}
		resourceTXT = ResourceTXT{
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
		resourceCNAME = ResourceCNAME{CNAME: MustParseName("www.example.com")}
		resourceMX    = ResourceMX{Pref: 54831, MX: MustParseName("smtp.example.com")}
		resourceOPT   = ResourceOPT{Options: []EDNS0Option{
			&EDNS0ClientSubnet{Family: AddressFamilyIPv4, SourcePrefixLength: 2, ScopePrefixLength: 3, Address: []byte{192, 0, 2, 1}},
			&EDNS0Cookie{
				ClientCookie:                 [8]byte{21, 200, 93, 34, 5, 219, 17, 28},
				ServerCookie:                 [32]byte{1, 2, 3, 4, 5, 6, 7, 99, 234, 139, 99, 119},
				ServerCookieAdditionalLength: 12,
			},
			&EDNS0ExtendedDNSError{InfoCode: 1, ExtraText: []byte("some error Text")},
		}}
	)

	sectionNames := []string{"Answers", "Authorities", "Additionals"}
	for i, nextSection := range []func(){b.StartAnswers, b.StartAuthorities, b.StartAdditionals} {
		sectionName := sectionNames[i]
		nextSection()

		rhdr.TTL = 32383739
		if err := b.ResourceA(rhdr, resourceA); err != nil {
			t.Fatalf("%v section, b.ResourceA() unexpected error: %v", sectionName, err)
		}
		testAfterAppend(sectionName)

		rhdr.TTL = 3600
		if err := b.ResourceAAAA(rhdr, resourceAAAA); err != nil {
			t.Fatalf("%v section, b.ResourceAAAA() unexpected error: %v", sectionName, err)
		}
		testAfterAppend(sectionName)

		if err := b.ResourceNS(rhdr, resourceNS); err != nil {
			t.Fatalf("%v section, b.ResourceNS() unexpected error: %v", sectionName, err)
		}
		testAfterAppend(sectionName)

		if err := b.ResourceSOA(rhdr, resourceSOA); err != nil {
			t.Fatalf("%v section, b.ResourceSOA() unexpected error: %v", sectionName, err)
		}
		testAfterAppend(sectionName)

		if err := b.ResourcePTR(rhdr, resourcePTR); err != nil {
			t.Fatalf("%v section, b.ResourcePTR() unexpected error: %v", sectionName, err)
		}
		testAfterAppend(sectionName)

		if err := b.ResourceTXT(rhdr, resourceTXT); err != nil {
			t.Fatalf("%v section, b.ResourceTXT() unexpected error: %v", sectionName, err)
		}
		testAfterAppend(sectionName)

		if err := b.RawResourceTXT(rhdr, rawResourceTXT); err != nil {
			t.Fatalf("%v section, b.RawResourceTXT() unexpected error: %v", sectionName, err)
		}
		testAfterAppend(sectionName)

		if err := b.ResourceCNAME(rhdr, resourceCNAME); err != nil {
			t.Fatalf("%v section, b.ResourceCNAME() unexpected error: %v", sectionName, err)
		}
		testAfterAppend(sectionName)

		if err := b.ResourceMX(rhdr, resourceMX); err != nil {
			t.Fatalf("%v section, b.ResourceMX() unexpected error: %v", sectionName, err)
		}
		testAfterAppend(sectionName)

		if err := b.ResourceOPT(rhdr, resourceOPT); err != nil {
			t.Fatalf("%v section, b.ResourceMX() unexpected error: %v", sectionName, err)
		}
		testAfterAppend(sectionName)
	}

	msg := b.Bytes()

	if !bytes.Equal(msg[:startLength], make([]byte, startLength)) {
		t.Fatal("builder modified msg[:startLength]")
	}

	p, hdr, err := Parse(msg[startLength:])
	if err != nil {
		t.Fatalf("Parse(): unexpected error: %v", err)
	}

	if hdr != expectHeader {
		t.Fatalf("Parse() unexpected header: %#v, want: %#v", hdr, expectHeader)
	}

	q, err := p.Question()
	if err != nil {
		t.Fatalf("p.Question() unexpected error: %v", err)
	}

	n := MustParseName("example.com.")
	if !q.Name.Equal(&n) {
		t.Errorf(`q.Name = %v, q.Name.Equal("example.com") = false, want: true`, q.Name.String())
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

		n := MustParseName("example.com.")
		if !rhdr.Name.Equal(&n) {
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

	sectionNames = []string{"Questions", "Answers", "Authorities", "Additionals"}
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
		equalRData(t, "p.ResourceA()", resourceA, resA)

		parseResourceHeader(curSectionName, TypeAAAA, ClassIN, 3600)
		resAAAA, err := p.ResourceAAAA()
		if err != nil {
			t.Fatalf("%v section, p.ResourceAAAA(): unexpected error: %v", curSectionName, err)
		}
		equalRData(t, "p.ResourceAAAA()", resourceAAAA, resAAAA)

		parseResourceHeader(curSectionName, TypeNS, ClassIN, 3600)
		resNS, err := p.ResourceNS()
		if err != nil {
			t.Fatalf("%v section, p.ResourceNS(): unexpected error: %v", curSectionName, err)
		}
		equalRData(t, "p.ResourceNS()", resourceNS, resNS)

		parseResourceHeader(curSectionName, TypeSOA, ClassIN, 3600)
		resSOA, err := p.ResourceSOA()
		if err != nil {
			t.Fatalf("%v section, p.ResourceSOA(): unexpected error: %v", curSectionName, err)
		}
		equalRData(t, "p.ResourceSOA()", resourceSOA, resSOA)

		parseResourceHeader(curSectionName, TypePTR, ClassIN, 3600)
		resPTR, err := p.ResourcePTR()
		if err != nil {
			t.Fatalf("%v section, p.ResourcePTR(): unexpected error: %v", curSectionName, err)
		}
		equalRData(t, "p.ResourcePTR()", resourcePTR, resPTR)

		parseResourceHeader(curSectionName, TypeTXT, ClassIN, 3600)
		resRawTXT, err := p.RawResourceTXT()
		if err != nil {
			t.Fatalf("%v section, p.RawResourceTXT(): unexpected error: %v", curSectionName, err)
		}
		equalRData(t, "p.RawResourceTXT() 1", rawResourceTXT, resRawTXT)

		parseResourceHeader(curSectionName, TypeTXT, ClassIN, 3600)
		resTXT, err := p.RawResourceTXT()
		if err != nil {
			t.Fatalf("%v section, p.RawResourceTXT(): unexpected error: %v", curSectionName, err)
		}
		equalRData(t, "p.RawResourceTXT() 2", rawResourceTXT, resTXT)

		parseResourceHeader(curSectionName, TypeCNAME, ClassIN, 3600)
		resCNAME, err := p.ResourceCNAME()
		if err != nil {
			t.Fatalf("%v section, p.ResourceCNAME(): unexpected error: %v", curSectionName, err)
		}
		equalRData(t, "p.ResourceCNAME()", resourceCNAME, resCNAME)

		parseResourceHeader(curSectionName, TypeMX, ClassIN, 3600)
		resMX, err := p.ResourceMX()
		if err != nil {
			t.Fatalf("%v section, p.ResourceMX(): unexpected error: %v", curSectionName, err)
		}
		equalRData(t, "p.ResourceMX()", resourceMX, resMX)

		parseResourceHeader(curSectionName, TypeOPT, ClassIN, 3600)
		resOPT, err := p.ResourceOPT()
		if err != nil {
			t.Fatalf("%v section, p.ResourceOPT(): unexpected error: %v", curSectionName, err)
		}
		if len(resOPT.Options) != len(resourceOPT.Options) {
			t.Fatalf("%v section, p.ResourceOPT() = %#v, want: %#v", curSectionName, resOPT, resourceOPT)
		}
		for i := 0; i < len(resOPT.Options); i++ {
			equalRData(t, fmt.Sprintf("p.ResourceOPT().Options[%v]", i), resourceOPT.Options[i], resOPT.Options[i])
		}
	}

	if err := p.End(); err != nil {
		t.Fatalf("p.End() unexpected error: %v", err)
	}
}

func equalRData(t *testing.T, name string, r1, r2 any) {
	r1val := reflect.ValueOf(r1)
	r2val := reflect.ValueOf(r2)

	if r1val.Kind() == reflect.Pointer {
		r1val = r1val.Elem()
		r2val = r2val.Elem()
	}

	if r1val.NumField() != r2val.NumField() {
		t.Fatal("different amount of fields")
	}

	for i := 0; i < r1val.NumField(); i++ {
		fieldName := r1val.Type().Field(i).Name

		if fieldName != r2val.Type().Field(i).Name {
			t.Fatal("different field names")
		}

		r1Field := r1val.Field(i)
		r2Field := r2val.Field(i)

		if rawName, ok := r1Field.Interface().(Name); ok {
			parserName := r2Field.Interface().(Name)

			if !bytes.Equal(parserName.asSlice(), rawName.asSlice()) {
				t.Errorf("%v: %v.%v = %v, want: %v ", name, r1val.Type().Name(), fieldName, rawName, rawName)
			}

			continue
		}

		if b, ok := r1Field.Interface().([]byte); ok {
			b2 := r2Field.Interface().([]byte)

			if !bytes.Equal(b2, b) {
				t.Errorf("%v: %v.%v = %v, want: %v ", name, r1val.Type().Name(), fieldName, b2, b)
			}

			continue
		}

		if !r1Field.Equal(r2Field) {
			t.Errorf("%v: %v.%v = %v, want: %v ", name, r1val.Type().Name(), fieldName, r1Field.Interface(), r2Field.Interface())
		}
	}
}

func TestBuilderRDBuilder(t *testing.T) {
	expectPanic := func(name string, f func()) {
		defer func() {
			if recover() == nil {
				t.Fatalf("%v: didn't panic", name)
			}
		}()
		f()
	}

	b := StartBuilder(make([]byte, 0, 512), 0, 0)
	b.StartAnswers()

	rdb, err := b.RDBuilder(ResourceHeader{
		Name:  MustParseName("www.example.com"),
		Type:  54839,
		Class: ClassIN,
	})
	if err != nil {
		t.Fatalf("b.RDBuilder() unexpected error: %v", err)
	}

	expectPanic("b.ResourceA", func() {
		b.ResourceA(ResourceHeader{
			Name:  MustParseName("example.com"),
			Class: ClassIN,
		}, ResourceA{})
	})

	if len(b.Bytes()) != 12 || b.Length() != 12 || b.Header() != *new(Header) {
		t.Fatalf("changes caused by RDBuilder visible before End()")
	}

	if err := rdb.Name(MustParseName("mx1.example.com"), true); err != nil {
		t.Fatalf("rb.Name() unexpected error: %v", err)
	}

	if len(b.Bytes()) != 12 || b.Length() != 12 || b.Header() != *new(Header) {
		t.Fatalf("changes caused by RDBuilder visible before End()")
	}

	if err := rdb.Bytes([]byte{1, 2, 3}); err != nil {
		t.Fatalf("rb.Bytes() unexpected error: %v", err)
	}

	if len(b.Bytes()) != 12 || b.Length() != 12 || b.Header() != *new(Header) {
		t.Fatalf("changes caused by RDBuilder visible before End()")
	}

	expectPanic("b.ResourceA", func() {
		b.ResourceA(ResourceHeader{
			Name:  MustParseName("example.com"),
			Class: ClassIN,
		}, ResourceA{})
	})

	if len(b.Bytes()) != 12 || b.Length() != 12 || b.Header() != *new(Header) {
		t.Fatalf("changes caused by RDBuilder visible before End()")
	}

	rdb.Remove()

	rdb, err = b.RDBuilder(ResourceHeader{
		Name:  MustParseName("example.com"),
		Type:  54839,
		Class: ClassIN,
	})
	if err != nil {
		t.Fatalf("b.RDBuilder() unexpected error: %v", err)
	}

	if len(b.Bytes()) != 12 || b.Length() != 12 || b.Header() != *new(Header) {
		t.Fatalf("changes caused by RDBuilder visible before End()")
	}

	expectPanic("b.ResourceA", func() {
		b.ResourceA(ResourceHeader{
			Name:  MustParseName("example.com"),
			Class: ClassIN,
		}, ResourceA{})
	})

	if err := rdb.Name(MustParseName("www.example.com"), true); err != nil {
		t.Fatalf("rb.Name() unexpected error: %v", err)
	}
	if len(b.Bytes()) != 12 || b.Length() != 12 || b.Header() != *new(Header) {
		t.Fatalf("changes caused by RDBuilder visible before End()")
	}

	if err := rdb.Bytes([]byte{128, 238, 197}); err != nil {
		t.Fatalf("rb.Bytes() unexpected error: %v", err)
	}
	if len(b.Bytes()) != 12 || b.Length() != 12 || b.Header() != *new(Header) {
		t.Fatalf("changes caused by RDBuilder visible before End()")
	}

	if err := rdb.Name(MustParseName("smtp.example.com"), false); err != nil {
		t.Fatalf("rb.Name() unexpected error: %v", err)
	}
	if len(b.Bytes()) != 12 || b.Length() != 12 || b.Header() != *new(Header) {
		t.Fatalf("changes caused by RDBuilder visible before End()")
	}

	if err := rdb.Uint8(237); err != nil {
		t.Fatalf("rb.Uint8() unexpected error: %v", err)
	}
	if len(b.Bytes()) != 12 || b.Length() != 12 || b.Header() != *new(Header) {
		t.Fatalf("changes caused by RDBuilder visible before End()")
	}

	if err := rdb.Uint16(23837); err != nil {
		t.Fatalf("rb.Uint16() unexpected error: %v", err)
	}
	if len(b.Bytes()) != 12 || b.Length() != 12 || b.Header() != *new(Header) {
		t.Fatalf("changes caused by RDBuilder visible before End()")
	}

	if err := rdb.Uint32(3847323837); err != nil {
		t.Fatalf("rb.Uint32() unexpected error: %v", err)
	}
	if len(b.Bytes()) != 12 || b.Length() != 12 || b.Header() != *new(Header) {
		t.Fatalf("changes caused by RDBuilder visible before End()")
	}

	if err := rdb.Uint64(3874898383473443); err != nil {
		t.Fatalf("rb.Uint64() unexpected error: %v", err)
	}
	if len(b.Bytes()) != 12 || b.Length() != 12 || b.Header() != *new(Header) {
		t.Fatalf("changes caused by RDBuilder visible before End()")
	}

	expectPanic("b.ResourceA", func() {
		b.ResourceA(ResourceHeader{
			Name:  MustParseName("example.com"),
			Class: ClassIN,
		}, ResourceA{})
	})

	if len(b.Bytes()) != 12 || b.Length() != 12 || b.Header() != *new(Header) {
		t.Fatalf("changes caused by RDBuilder visible before End()")
	}

	rdb.End()

	if err := b.ResourceA(ResourceHeader{
		Name:  MustParseName("example.com"),
		Class: ClassIN,
	}, ResourceA{}); err != nil {
		t.Fatalf("b.ResourceA() unexpected error: %v", err)
	}

	expectPanic("rb.End()", func() { rdb.End() })
	expectPanic("rb.Remove()", func() { rdb.Remove() })
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

	n := MustParseName("www.example.com")
	if !name.Equal(&n) {
		t.Errorf(`name = %v, name.Equal("www.example.com") = false, want: true`, name.String())
	}

	if name.Compression != CompressionCompressed {
		t.Errorf("name.Compression = %v, want: Compressed", name.Compression)
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

	n = MustParseName("smtp.example.com.")
	if !name2.Equal(&n) {
		t.Errorf(`name2 = %v, name2.Equal("smtp.example.com") = false, want: true`, name2.String())
	}

	if name2.Compression != CompressionNotCompressed {
		t.Errorf("name.Compression = %v, want: NotCompressed", name2.Compression)
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
	rdb, err := b.RDBuilder(ResourceHeader{
		Name:   MustParseName("."),
		Type:   54839,
		Class:  ClassIN,
		Length: 100,
	})
	if err != nil {
		t.Fatalf("b.RDBuilder() unexpected error: %v", err)
	}

	rdb.Bytes(make([]byte, math.MaxUint16-6))
	before := b.Bytes()[12:]

	if err := rdb.Name(MustParseName("www.example.com"), true); err == nil {
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

func TestBuilderReset(t *testing.T) {
	b := StartBuilder(make([]byte, 0, 128), 0, 0)
	b.LimitMessageSize(100)

	if err := b.Question(Question{
		Name:  MustParseName("example.net"),
		Type:  TypeA,
		Class: ClassIN,
	}); err != nil {
		t.Fatalf("b.Question() returned error: %v", err)
	}

	hdr := ResourceHeader{
		Name:  MustParseName("example.com"),
		Class: ClassIN,
	}

	b.StartAnswers()
	if err := b.ResourceA(hdr, ResourceA{A: [4]byte{192, 0, 2, 1}}); err != nil {
		t.Fatalf("b.ResourceA() returned error: %v", err)
	}
	b.StartAuthorities()
	hdr.Name = MustParseName("www.example.com")
	if err := b.ResourceA(hdr, ResourceA{A: [4]byte{192, 0, 2, 1}}); err != nil {
		t.Fatalf("b.ResourceA() returned error: %v", err)
	}
	b.StartAdditionals()
	hdr.Name = MustParseName("smtp.example.com")
	if err := b.ResourceA(hdr, ResourceA{A: [4]byte{192, 0, 2, 1}}); err != nil {
		t.Fatalf("b.ResourceA() returned error: %v", err)
	}
	hdr.Name = MustParseName("internal.example.com")
	if err := b.ResourceA(hdr, ResourceA{A: [4]byte{192, 0, 2, 1}}); err != ErrTruncated {
		t.Fatalf("b.ResourceA() returned error: %v, want: %v", err, ErrTruncated)
	}

	b.Reset(make([]byte, 0, 128), 0, 0)

	if err := b.Question(Question{
		Name:  MustParseName("www.example.net"),
		Type:  TypeA,
		Class: ClassIN,
	}); err != nil {
		t.Fatalf("b.Question() returned error: %v", err)
	}

	b.StartAnswers()
	hdr.Name = MustParseName("internal.example.com")
	if err := b.ResourceAAAA(hdr, ResourceAAAA{}); err != nil {
		t.Fatalf("b.ResourceA() returned error: %v", err)
	}
	b.StartAuthorities()
	hdr.Name = MustParseName("www.example.com")
	if err := b.ResourceAAAA(hdr, ResourceAAAA{}); err != nil {
		t.Fatalf("b.ResourceA() returned error: %v", err)
	}
	b.StartAdditionals()
	hdr.Name = MustParseName("example.com")
	if err := b.ResourceAAAA(hdr, ResourceAAAA{}); err != nil {
		t.Fatalf("b.ResourceA() returned error: %v", err)
	}
	hdr.Name = MustParseName("www.admin.internal.example.net")
	if err := b.ResourceA(hdr, ResourceA{A: [4]byte{192, 0, 2, 1}}); err != nil {
		t.Fatalf("b.ResourceA() returned error: %v", err)
	}

	p, _, err := Parse(b.Bytes())
	if err != nil {
		t.Fatalf("Parse() returned error: %v", err)
	}

	q, err := p.Question()
	if err != nil {
		t.Fatalf("p.Question() returned error: %v", err)
	}

	n := MustParseName("www.example.net")
	if !q.Name.Equal(&n) {
		t.Fatalf(`hdr1.Name = %v, hdr1.Name.Equal("www.example.net") = false, want: true`, q.Name.String())
	}

	if q.Class != ClassIN {
		t.Fatalf("q.Class = %v, want: %v", q.Class, ClassIN)
	}

	if q.Type != TypeA {
		t.Fatalf("q.Type = %v, want: %v", q.Type, TypeA)
	}

	if err := p.StartAnswers(); err != nil {
		t.Fatalf("p.StartAnswers() returned error: %v", err)
	}

	hdr1, err := p.ResourceHeader()
	if err != nil {
		t.Fatalf("p.ResourceHeader() returned error: %v", err)
	}

	n = MustParseName("internal.example.com")
	if !hdr1.Name.Equal(&n) {
		t.Fatalf(`hdr1.Name = %v, hdr1.Name.Equal("internal.example.com") = false, want: true`, hdr1.Name.String())
	}

	if hdr1.Class != ClassIN {
		t.Fatalf("hdr1.Class = %v, want: %v", hdr1.Class, ClassIN)
	}

	if hdr1.Type != TypeAAAA {
		t.Fatalf("hdr1.Type = %v, want: %v", hdr1.Type, TypeAAAA)
	}

	if _, err := p.ResourceAAAA(); err != nil {
		t.Fatalf("p.ResourceAAAA() returned error: %v", err)
	}

	p.StartAuthorities()
	hdr2, err := p.ResourceHeader()
	if err != nil {
		t.Fatalf("p.ResourceHeader() returned error: %v", err)
	}

	n = MustParseName("www.example.com")
	if !hdr2.Name.Equal(&n) {
		t.Fatalf(`hdr2.Name = %v, hdr2.Name.Equal("www.example.com") = false, want: true`, hdr2.Name.String())
	}

	if _, err := p.ResourceAAAA(); err != nil {
		t.Fatalf("p.ResourceAAAA() returned error: %v", err)
	}

	p.StartAdditionals()
	hdr3, err := p.ResourceHeader()
	if err != nil {
		t.Fatalf("p.ResourceHeader() returned error: %v", err)
	}

	n = MustParseName("example.com")
	if !hdr3.Name.Equal(&n) {
		t.Fatalf(`hdr3.Name = %v, hdr3.Name.Equal("example.com") = false, want: true`, hdr3.Name.String())
	}

	if _, err := p.ResourceAAAA(); err != nil {
		t.Fatalf("p.ResourceAAAA() returned error: %v", err)
	}

	hdr4, err := p.ResourceHeader()
	if err != nil {
		t.Fatalf("p.ResourceHeader() returned error: %v", err)
	}

	n = MustParseName("www.admin.internal.example.net")
	if !hdr4.Name.Equal(&n) {
		t.Fatalf(`hdr4.Name = %v, hdr4.Name.Equal("www.admin.internal.example.net") = false, want: true`, hdr4.Name.String())
	}

	if _, err := p.ResourceA(); err != nil {
		t.Fatalf("p.ResourceA() returned error: %v", err)
	}

	if err := p.End(); err != nil {
		t.Fatalf("p.End() returned error: %v", err)
	}
}

type fuzzRand struct {
	t    *testing.T
	rand []byte
}

func (r *fuzzRand) bool() bool {
	return r.uint8() > 127
}

func (r *fuzzRand) uint8() uint8 {
	if len(r.rand) == 0 {
		r.t.SkipNow()
	}
	val := r.rand[0]
	r.rand = r.rand[1:]
	return val
}

func (r *fuzzRand) uint16() uint16 {
	if len(r.rand) < 2 {
		r.t.SkipNow()
	}
	val := binary.BigEndian.Uint16(r.rand)
	r.rand = r.rand[2:]
	return val
}

func (r *fuzzRand) uint32() uint32 {
	if len(r.rand) < 4 {
		r.t.SkipNow()
	}
	val := binary.BigEndian.Uint32(r.rand)
	r.rand = r.rand[4:]
	return val
}

func (r *fuzzRand) arbitraryAmountOfBytes() []byte {
	count := r.uint32()
	if int(count) > len(r.rand) {
		count = uint32(len(r.rand))
	}

	b := r.rand[:count:count]
	r.rand = r.rand[count:]
	return b
}

func (r *fuzzRand) bytes(n int) []byte {
	if len(r.rand) < n {
		return make([]byte, n)
	}
	b := r.rand[:n:n]
	r.rand = r.rand[n:]
	return b
}

func (r *fuzzRand) rawName() Name {
	n, err := ParseName(string(r.arbitraryAmountOfBytes()))
	if err != nil {
		r.t.SkipNow()
	}
	return n
}

func FuzzBuilder(f *testing.F) {
	f.Fuzz(func(t *testing.T, rand []byte) {
		r := fuzzRand{t, rand}
		start := r.arbitraryAmountOfBytes()
		additionalAvailCapacity := r.uint16()
		buf := append(start, make([]byte, additionalAvailCapacity)...)[:len(start)]

		id := r.uint16()
		flags := r.uint16()

		if debugFuzz {
			t.Logf("creating builder with len(buf) = %v, cap(buf) = %v, id = %v, flags = %v", len(buf), cap(buf), id, Flags(flags))
		}

		b := StartBuilder(buf, id, Flags(flags))

		sizeLimit := int(r.uint16())
		if sizeLimit >= 12 {
			if debugFuzz {
				t.Logf("b.LimitMessageSize(%v)", sizeLimit)
			}
			b.LimitMessageSize(sizeLimit)
		}

		for r.bool() {
			if r.bool() {
				flags = r.uint16()
				if debugFuzz {
					t.Logf("b.SetFlags(%v)", Flags(flags))
				}
				b.SetFlags(Flags(flags))
			}
			if r.bool() {
				id = r.uint16()
				if debugFuzz {
					t.Logf("b.SetId(%v)", id)
				}
				b.SetID(id)
			}

			beforeLen := b.Length()
			before := b.Bytes()

			q := Question{
				Name:  r.rawName(),
				Type:  Type(r.uint16()),
				Class: Class(r.uint16()),
			}

			err := b.Question(q)
			if err != nil {
				if err == errResourceCountLimitReached {
					continue
				}
				if err == ErrTruncated && (!bytes.Equal(append([]byte{}, before...), b.Bytes()) || beforeLen != b.Length()) {
					t.Fatalf("b.Question() modified the message after the: %v error", ErrTruncated)
				}
				if err != ErrTruncated {
					t.Fatalf("b.Question() returned error: %v", err)
				}
			}

			if debugFuzz {
				t.Logf("b.Question(%#v) = %v", q, err)
			}

			if sizeLimit >= 12 && b.Length() > sizeLimit {
				t.Fatalf("message size: %v is bigger than the message size limit: %v", b.Length(), sizeLimit)
			}

			if newSizeLimit := sizeLimit + int(r.uint16()); newSizeLimit >= 12 && newSizeLimit >= b.Length() {
				if debugFuzz {
					t.Logf("b.LimitMessageSize(%v)", newSizeLimit)
				}
				sizeLimit = newSizeLimit
				b.LimitMessageSize(sizeLimit)
			}
		}

		sectionNames := []string{"Answers", "Authorities", "Additionals"}
	nextSection:
		for i, nextSection := range []func(){b.StartAnswers, b.StartAuthorities, b.StartAdditionals} {
			sectionName := sectionNames[i]
			if debugFuzz {
				t.Logf("b.Start%v()", sectionName)
			}
			nextSection()

			if r.bool() {
				flags = r.uint16()
				if debugFuzz {
					t.Logf("b.SetFlags(%v)", Flags(flags))
				}
				b.SetFlags(Flags(flags))
			}
			if r.bool() {
				id = r.uint16()
				if debugFuzz {
					t.Logf("b.SetId(%v)", id)
				}
				b.SetID(id)
			}

			for r.bool() {
				hdr := ResourceHeader{
					Name:  r.rawName(),
					Class: Class(r.uint16()),
					TTL:   r.uint32(),
				}

				beforeLen := b.Length()
				before := b.Bytes()

				var err error
				v := r.uint8()
				switch v {
				case 1:
					res := ResourceA{A: [4]byte(r.bytes(4))}
					err = b.ResourceA(hdr, res)
					if debugFuzz {
						t.Logf("b.ResourceA(%#v, %#v) = %v", hdr, res, err)
					}
				case 2:
					res := ResourceAAAA{AAAA: [16]byte(r.bytes(16))}
					err = b.ResourceAAAA(hdr, res)
					if debugFuzz {
						t.Logf("b.ResourceAAAA(%#v, %#v) = %v", hdr, res, err)
					}
				case 3:
					res := ResourceNS{NS: r.rawName()}
					err = b.ResourceNS(hdr, res)
					if debugFuzz {
						t.Logf("b.ResourceNS(%#v, %#v) = %v", hdr, res, err)
					}
				case 4:
					res := ResourceSOA{
						NS:      r.rawName(),
						Mbox:    r.rawName(),
						Serial:  r.uint32(),
						Refresh: r.uint32(),
						Retry:   r.uint32(),
						Expire:  r.uint32(),
						Minimum: r.uint32(),
					}
					err = b.ResourceSOA(hdr, res)
					if debugFuzz {
						t.Logf("b.ResourceSOA(%#v, %#v) = %v", hdr, res, err)
					}
				case 5:
					count := r.uint16()
					txt := ResourceTXT{
						TXT: make([][]byte, count),
					}
					for i := range txt.TXT {
						txt.TXT[i] = r.arbitraryAmountOfBytes()
					}
					err = b.ResourceTXT(hdr, txt)
					if debugFuzz {
						t.Logf("b.ResourceTXT(%#v, %#v) = %v", hdr, txt, err)
					}
					if err == errTooLongTXTString || err == errTooLongTXT || err == errEmptyTXT {
						err = nil
					}
				case 6:
					res := RawResourceTXT{TXT: r.arbitraryAmountOfBytes()}
					err = b.RawResourceTXT(hdr, res)
					if debugFuzz {
						t.Logf("b.RawResourceTXT(%#v, %#v) = %v", hdr, res, err)
					}
					if err == errInvalidRawTXTResource {
						err = nil
					}
				case 7:
					res := ResourceCNAME{CNAME: r.rawName()}
					err = b.ResourceCNAME(hdr, res)
					if debugFuzz {
						t.Logf("b.ResourceCNAME(%#v, %#v) = %v", hdr, res, err)
					}
				case 8:
					res := ResourceMX{Pref: r.uint16(), MX: r.rawName()}
					err = b.ResourceMX(hdr, res)
					if debugFuzz {
						t.Logf("b.ResourceMX(%#v, %#v) = %v", hdr, res, err)
					}
				case 9:
					res := ResourceOPT{}
					for r.bool() {
						switch r.uint8() {
						case 0:
							res.Options = append(res.Options, &EDNS0ClientSubnet{
								Family:             AddressFamily(r.uint8()),
								SourcePrefixLength: r.uint8(),
								ScopePrefixLength:  r.uint8(),
								Address:            r.arbitraryAmountOfBytes(),
							})
						case 2:
							res.Options = append(res.Options, &EDNS0Cookie{
								ClientCookie:                 [8]byte(r.bytes(8)),
								ServerCookie:                 [32]byte(r.bytes(32)),
								ServerCookieAdditionalLength: r.uint8(),
							})
						case 3:
							res.Options = append(res.Options, &EDNS0ExtendedDNSError{
								InfoCode:  ExtendedDNSErrorCode(r.uint16()),
								ExtraText: r.arbitraryAmountOfBytes(),
							})
						}
					}
					err = b.ResourceOPT(hdr, res)
					if debugFuzz {
						t.Logf("b.ResourceOPT(%#v, %#v) = %v", hdr, res, err)
					}
				default:
					continue nextSection
				}

				if err != nil {
					if err == errResourceCountLimitReached {
						continue
					}
					if err == ErrTruncated && (!bytes.Equal(append([]byte{}, before...), b.Bytes()) || beforeLen != b.Length()) {
						t.Fatalf("%v section, resource appending modified the message after the: %v error", sectionName, ErrTruncated)
					}
					if err != ErrTruncated {
						t.Fatalf("%v section, at %v, unexpected resource appending error: %v", sectionName, v, err)
					}
				}

				if sizeLimit >= 12 && b.Length() > sizeLimit {
					t.Fatalf("message size: %v is bigger than the message size limit: %v", b.Length(), sizeLimit)
				}

				if newSizeLimit := sizeLimit + int(r.uint16()); newSizeLimit >= 12 && newSizeLimit >= b.Length() {
					sizeLimit = newSizeLimit
					b.LimitMessageSize(sizeLimit)
				}
			}
		}

		p, hdr, err := Parse(b.Bytes()[len(start):])
		if err != nil {
			t.Fatalf("Parse() returned error: %v", err)
		}

		if hdr.ID != id {
			t.Fatalf("Parse(): unexpected id in header: %v, want: %v", hdr.ID, id)
		}

		if hdr.Flags != Flags(flags) {
			t.Fatalf("Parse(): unexpected flags in header: %v, want: %v", hdr.Flags, Flags(flags))
		}

		for {
			t.Log(p.msg)
			_, err := p.Question()
			if err != nil {
				if err == ErrSectionDone {
					break
				}
				t.Fatalf("p.Question() returned error: %v", err)
			}
		}

		sectionNames = []string{"Answers", "Authorities", "Additionals"}
		for i, nextSection := range []func() error{p.StartAnswers, p.StartAuthorities, p.StartAdditionals} {
			sectionName := sectionNames[i]
			if err := nextSection(); err != nil {
				t.Fatalf("p.Start%v() returned error: %v", sectionName, err)
			}

			for {
				rhdr, err := p.ResourceHeader()
				if err != nil {
					if err == ErrSectionDone {
						break
					}
					t.Fatalf("p.ResourceHeader() returned error: %v", err)
				}

				switch rhdr.Type {
				case TypeA:
					_, err = p.ResourceA()
				case TypeAAAA:
					_, err = p.ResourceAAAA()
				case TypeNS:
					_, err = p.ResourceNS()
				case TypeCNAME:
					_, err = p.ResourceCNAME()
				case TypeMX:
					_, err = p.ResourceMX()
				case TypeTXT:
					_, err = p.RawResourceTXT()
				case TypeOPT:
					_, err = p.ResourceOPT()
				default:
					err = p.SkipResourceData()
				}

				if err != nil {
					t.Fatalf("%v section, %v resource, resource data parsing returned error: %v", sectionName, rhdr.Type, err)
				}
			}
		}
	})
}
