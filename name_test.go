package dnsmsg

import (
	"bytes"
	"fmt"
	"math"
	"strings"
	"testing"
)

func TestParseName(t *testing.T) {
	escapes := "\\.\\223\\.\\\\"
	escapesCharCount := 4
	label54 := escapes + strings.Repeat("a", 54-escapesCharCount)
	label63 := escapes + strings.Repeat("a", 63-escapesCharCount)
	label64 := escapes + strings.Repeat("a", 64-escapesCharCount)
	label54Encoded := append([]byte{54, '.', 223, '.', '\\'}, strings.Repeat("a", 54-escapesCharCount)...)
	label63Encoded := append([]byte{63, '.', 223, '.', '\\'}, strings.Repeat("a", 63-escapesCharCount)...)

	cases := []struct {
		in        string
		expect    Name
		expectErr error
	}{
		{in: ".", expect: Name{Length: 1}},
		{in: "a.", expect: Name{Name: [255]byte{1, 'a', 0}, Length: 3}},
		{in: "aa.", expect: Name{Name: [255]byte{2, 'a', 'a', 0}, Length: 4}},
		{in: "aA.", expect: Name{Name: [255]byte{2, 'a', 'A', 0}, Length: 4}},
		{in: "a", expect: Name{Name: [255]byte{1, 'a', 0}, Length: 3}},
		{in: "aa", expect: Name{Name: [255]byte{2, 'a', 'a', 0}, Length: 4}},
		{in: "aA", expect: Name{Name: [255]byte{2, 'a', 'A', 0}, Length: 4}},

		{in: "example.com.", expect: Name{Name: [255]byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}, Length: 13}},
		{in: "example.com", expect: Name{Name: [255]byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}, Length: 13}},
		{in: "exAMPle.cOm.", expect: Name{Name: [255]byte{7, 'e', 'x', 'A', 'M', 'P', 'l', 'e', 3, 'c', 'O', 'm', 0}, Length: 13}},
		{in: "exAMPle.cOm", expect: Name{Name: [255]byte{7, 'e', 'x', 'A', 'M', 'P', 'l', 'e', 3, 'c', 'O', 'm', 0}, Length: 13}},

		{in: "www.example.com.", expect: Name{Name: [255]byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}, Length: 17}},
		{in: "www.example.com", expect: Name{Name: [255]byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}, Length: 17}},

		{in: "\\..", expect: Name{Name: [255]byte{1, '.', 0}, Length: 3}},
		{in: "\\\\.", expect: Name{Name: [255]byte{1, '\\', 0}, Length: 3}},
		{in: "\\a.", expect: Name{Name: [255]byte{1, 'a', 0}, Length: 3}},
		{in: "\\-.", expect: Name{Name: [255]byte{1, '-', 0}, Length: 3}},
		{in: "\\.", expect: Name{Name: [255]byte{1, '.', 0}, Length: 3}},
		{in: "\\\\", expect: Name{Name: [255]byte{1, '\\', 0}, Length: 3}},
		{in: "\\a", expect: Name{Name: [255]byte{1, 'a', 0}, Length: 3}},
		{in: "\\-", expect: Name{Name: [255]byte{1, '-', 0}, Length: 3}},

		{in: "\\000", expect: Name{Name: [255]byte{1, 0, 0}, Length: 3}},
		{in: "\\001", expect: Name{Name: [255]byte{1, 1, 0}, Length: 3}},
		{in: "\\041", expect: Name{Name: [255]byte{1, 41, 0}, Length: 3}},
		{in: "\\189", expect: Name{Name: [255]byte{1, 189, 0}, Length: 3}},
		{in: "\\241", expect: Name{Name: [255]byte{1, 241, 0}, Length: 3}},
		{in: "\\255", expect: Name{Name: [255]byte{1, 255, 0}, Length: 3}},

		{in: "\\1.", expectErr: errInvalidName},
		{in: "\\12.", expectErr: errInvalidName},
		{in: "\\1a.", expectErr: errInvalidName},
		{in: "\\12a.", expectErr: errInvalidName},
		{in: "\\256.", expectErr: errInvalidName},
		{in: "\\300.", expectErr: errInvalidName},

		{
			in:     "\\255\\.\\\\a\\a\\c\\..example.com.",
			expect: Name{Name: [255]byte{7, 255, '.', '\\', 'a', 'a', 'c', '.', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}, Length: 21},
		},

		{in: "example.com..", expectErr: errInvalidName},
		{in: "example..com.", expectErr: errInvalidName},
		{in: "www..example.com.", expectErr: errInvalidName},

		{
			in: label63 + ".go.dev",
			expect: func() (n Name) {
				s := append(n.Name[:0], label63Encoded...)
				s = append(s, 2, 'g', 'o', 3, 'd', 'e', 'v', 0)
				n.Length = byte(len(s))
				return
			}(),
		},
		{in: label64 + ".go.dev", expectErr: errInvalidName},

		{
			in: label63,
			expect: func() (n Name) {
				s := append(n.Name[:0], label63Encoded...)
				s = append(s, 0)
				n.Length = byte(len(s))
				return
			}(),
		},
		{
			in: label63 + ".",
			expect: func() (n Name) {
				s := append(n.Name[:0], label63Encoded...)
				s = append(s, 0)
				n.Length = byte(len(s))
				return
			}(),
		},
		{in: label64, expectErr: errInvalidName},
		{in: label64 + ".", expectErr: errInvalidName},

		// 253B non-rooted name.
		{
			in: fmt.Sprintf("%[1]v.%[1]v.%[1]v.%v.go.dev", label63, label54),
			expect: func() (n Name) {
				s := append(n.Name[:0], label63Encoded...)
				s = append(s, label63Encoded...)
				s = append(s, label63Encoded...)
				s = append(s, label54Encoded...)
				s = append(s, 2, 'g', 'o', 3, 'd', 'e', 'v', 0)
				n.Length = byte(len(s))
				return
			}(),
		},

		// 254B rooted name.
		{
			in: fmt.Sprintf("%[1]v.%[1]v.%[1]v.%v.go.dev.", label63, label54),
			expect: func() (n Name) {
				s := append(n.Name[:0], label63Encoded...)
				s = append(s, label63Encoded...)
				s = append(s, label63Encoded...)
				s = append(s, label54Encoded...)
				s = append(s, 2, 'g', 'o', 3, 'd', 'e', 'v', 0)
				n.Length = byte(len(s))
				return
			}(),
		},

		// 254B non-rooted name.
		{
			in:        fmt.Sprintf("%[1]v.%[1]v.%[1]v.%va.go.dev", label63, label54),
			expectErr: errInvalidName,
		},

		// 255B rooted name.
		{
			in:        fmt.Sprintf("%[1]v.%[1]v.%[1]v.%va.go.dev.", label63, label54),
			expectErr: errInvalidName,
		},
	}

	for _, tt := range cases {
		name, err := ParseName(tt.in)
		if err != tt.expectErr || name.Name != tt.expect.Name ||
			name.Length != tt.expect.Length || name.Compression != tt.expect.Compression {
			t.Errorf(
				"ParseName(%q) = (%v, %v); want = (%v, %v)",
				tt.in, name, err, tt.expect, tt.expectErr,
			)
		}
	}
}

func TestNameString(t *testing.T) {
	cases := []struct {
		n   Name
		str string
	}{
		{n: Name{}, str: ""},
		{n: Name{Length: 1}, str: "."},
		{n: Name{Name: [255]byte{1, 'a', 0}, Length: 3}, str: "a."},
		{n: Name{Name: [255]byte{2, 'a', 'A', 0}, Length: 3}, str: "aA."},
		{n: Name{Name: [255]byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}, Length: 13}, str: "example.com."},
		{n: Name{Name: [255]byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}, Length: 13}, str: "www.example.com."},
		{n: Name{Name: [255]byte{3, 'W', 'w', 'W', 7, 'e', 'X', 'a', 'm', 'p', 'L', 'e', 3, 'c', 'O', 'm', 0}, Length: 13}, str: "WwW.eXampLe.cOm."},
		{n: Name{Name: [255]byte{2, '~', '!', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}, Length: 13}, str: "~!.example.com."},
		{n: Name{Name: [255]byte{4, 0x20, 0x7F, '.', '\\', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}, Length: 13}, str: "\\032\\127\\.\\\\.example.com."},
	}

	for _, tt := range cases {
		if str := tt.n.String(); str != tt.str {
			t.Errorf("(%v).String() = %q; want = %q", tt.n.Name[:tt.n.Length], str, tt.str)
		}
	}
}

func TestNameEqual(t *testing.T) {
	cases := []struct {
		n1, n2 Name
		eq     bool
	}{
		{n1: Name{}, n2: Name{}, eq: true},
		{n1: Name{Length: 1}, n2: Name{Length: 1}, eq: true},
		{n1: Name{Length: 1}, n2: Name{}, eq: false},
		{
			n1: Name{Name: [255]byte{1, 'a', 0}, Length: 3},
			n2: Name{Name: [255]byte{1, 'a', 0}, Length: 3},
			eq: true,
		},
		{
			n1: Name{Name: [255]byte{1, 'a', 0}, Length: 3},
			n2: Name{Name: [255]byte{1, 'A', 0}, Length: 3},
			eq: true,
		},
		{
			n1: Name{Name: [255]byte{1, 'a', 0}, Length: 3},
			n2: Name{Name: [255]byte{1, 'b', 0}, Length: 3},
			eq: false,
		},
		{
			n1: Name{Name: [255]byte{1, 'a', 0}, Length: 3},
			n2: Name{Name: [255]byte{2, 'a', 'a', 0}, Length: 4},
			eq: false,
		},

		{
			n1: Name{
				Name:   [255]byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
				Length: 13,
			},
			n2: Name{
				Name:   [255]byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
				Length: 13,
			},
			eq: true,
		},
		{
			n1: Name{
				Name:   [255]byte{7, 'E', 'x', 'A', 'm', 'p', 'L', 'e', 3, 'c', 'O', 'm', 0},
				Length: 13,
			},
			n2: Name{
				Name:   [255]byte{7, 'E', 'X', 'a', 'm', 'p', 'l', 'E', 3, 'C', 'o', 'm', 0},
				Length: 13,
			},
			eq: true,
		},
		{
			n1: Name{
				Name:   [255]byte{3, 'w', 'w', 'w', 7, 'E', 'x', 'A', 'm', 'p', 'L', 'e', 3, 'c', 'O', 'm', 0},
				Length: 17,
			},
			n2: Name{
				Name:   [255]byte{7, 'E', 'X', 'a', 'm', 'p', 'l', 'E', 3, 'C', 'o', 'm', 0},
				Length: 13,
			},
			eq: false,
		},
		{
			n1: Name{
				Name:   [255]byte{3, 'w', 'w', 'w', 7, 'E', 'x', 'A', 'm', 'p', 'L', 'e', 3, 'c', 'O', 'm', 0},
				Length: 17,
			},
			n2: Name{
				Name:   [255]byte{4, 'i', 'm', 'a', 'p', 7, 'E', 'X', 'a', 'm', 'p', 'l', 'E', 3, 'C', 'o', 'm', 0},
				Length: 18,
			},
			eq: false,
		},
		{
			n1: Name{
				Name:   [255]byte{1, 'a', 2, 'w', 'w', 3, 'w', 'w', 'w', 0},
				Length: 10,
			},
			n2: Name{
				Name:   [255]byte{1, 'a', 3, 'w', 'w', 'w', 2, 'w', 'w', 0},
				Length: 10,
			},
			eq: false,
		},
	}

	for _, tt := range cases {
		if eq := tt.n1.Equal(&tt.n2); eq != tt.eq {
			t.Errorf("(%v).Equal(%v) = %v; want = %v",
				tt.n1.Name[:tt.n2.Length],
				tt.n2.Name[:tt.n2.Length],
				eq, tt.eq,
			)
		}
		if eq := tt.n2.Equal(&tt.n1); eq != tt.eq {
			t.Errorf("(%v).Equal(%v) = %v; want = %v",
				tt.n2.Name[:tt.n2.Length],
				tt.n1.Name[:tt.n1.Length],
				eq, tt.eq,
			)
		}
	}
}

func TestNameUnpack(t *testing.T) {
	a63 := bytes.Repeat([]byte{'a'}, 63)
	a61 := bytes.Repeat([]byte{'a'}, 61)

	var name255NoCompression []byte
	name255NoCompression = append(name255NoCompression, byte(len(a61)))
	name255NoCompression = append(name255NoCompression, a61...)
	for i := 0; i < 3; i++ {
		name255NoCompression = append(name255NoCompression, byte(len(a63)))
		name255NoCompression = append(name255NoCompression, a63...)
	}
	name255NoCompression = append(name255NoCompression, 0)

	if len(name255NoCompression) != 255 {
		panic("invalid name")
	}

	var name255Compressed []byte
	name255Compressed = append(name255Compressed, byte(len(a61)))
	name255Compressed = append(name255Compressed, a61...)
	name255Compressed = append(name255Compressed, 0xC0, byte(len(name255Compressed))+4)
	name255Compressed = append(name255Compressed, 32, 32) // random data
	for i := 0; i < 3; i++ {
		name255Compressed = append(name255Compressed, byte(len(a63)))
		name255Compressed = append(name255Compressed, a63...)
	}
	name255Compressed = append(name255Compressed, 0)

	// +4 (pointer and random data in-between")
	if len(name255Compressed) != 255+4 {
		panic("invalid name")
	}

	cases := []struct {
		msg       []byte
		nameStart int

		expectName   Name
		expectOffset uint16
		expectErr    error
	}{
		{
			msg:          []byte{0},
			expectName:   Name{Length: 1, Compression: CompressionNotCompressed},
			expectOffset: 1,
		},
		{
			msg:          []byte{0xC0, 3, 1, 0},
			expectName:   Name{Length: 1, Compression: CompressionCompressed},
			expectOffset: 2,
		},
		{
			msg:          []byte{1, 'a', 0},
			expectName:   Name{Name: [255]byte{1, 'a', 0}, Length: 3, Compression: CompressionNotCompressed},
			expectOffset: 3,
		},
		{
			msg:          []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			expectName:   Name{Name: [255]byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}, Length: 13, Compression: CompressionNotCompressed},
			expectOffset: 13,
		},
		{
			msg:          []byte{7, 'E', 'x', 'a', 'M', 'p', 'l', 'E', 3, 'c', 'O', 'M', 0},
			expectName:   Name{Name: [255]byte{7, 'E', 'x', 'a', 'M', 'p', 'l', 'E', 3, 'c', 'O', 'M', 0}, Length: 13, Compression: CompressionNotCompressed},
			expectOffset: 13,
		},
		{
			msg:          []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			expectName:   Name{Name: [255]byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}, Length: 17, Compression: CompressionNotCompressed},
			expectOffset: 17,
		},

		{
			msg:          []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 3, 'w', 'w', 'w', 0xC0, 0, 1, 1, 1},
			nameStart:    13,
			expectName:   Name{Name: [255]byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}, Length: 17, Compression: CompressionCompressed},
			expectOffset: 6,
		},
		{
			msg:          []byte{88, 99, 3, 'w', 'w', 'w', 0xC0, 10, 1, 1, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
			nameStart:    2,
			expectName:   Name{Name: [255]byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}, Length: 17, Compression: CompressionCompressed},
			expectOffset: 6,
		},

		{
			// 255 Byte name without pointers
			msg:          name255NoCompression,
			expectName:   Name{Name: [255]byte(name255NoCompression), Length: 255, Compression: CompressionNotCompressed},
			expectOffset: 255,
		},
		{
			// 255 Byte name with one compression pointer",
			msg:          name255Compressed,
			expectName:   Name{Name: [255]byte(name255NoCompression), Length: 255, Compression: CompressionCompressed},
			expectOffset: 64,
		},
		{
			// 256 Byte name without compression pointers
			msg: func() []byte {
				var buf []byte
				a63 := bytes.Repeat([]byte{'a'}, 63)
				a62 := bytes.Repeat([]byte{'a'}, 62)

				for i := 0; i < 3; i++ {
					buf = append(buf, byte(len(a63)))
					buf = append(buf, a63...)
				}

				buf = append(buf, byte(len(a62)))
				buf = append(buf, a62...)
				buf = append(buf, 0)

				if len(buf) != 256 {
					panic("invalid name")
				}

				return buf
			}(),
			expectErr: errInvalidDNSName,
		},
		{
			// 256 Byte name with one compression pointer
			msg: func() []byte {
				var buf []byte
				a63 := bytes.Repeat([]byte{'a'}, 63)
				z62 := bytes.Repeat([]byte{'z'}, 62)

				buf = append(buf, byte(len(z62)))
				buf = append(buf, z62...)
				buf = append(buf, 0xC0, byte(len(buf))+4)

				buf = append(buf, 32, 32) // random data

				for i := 0; i < 3; i++ {
					buf = append(buf, byte(len(a63)))
					buf = append(buf, a63...)
				}

				buf = append(buf, 0)

				// +4 (pointer and random data in-between")
				if len(buf) != 256+4 {
					panic("invalid name")
				}

				return buf
			}(),
			expectErr: errInvalidDNSName,
		},

		{msg: []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 5, 'c', 'o', 'm', 0}, expectErr: errInvalidDNSName},
		{msg: []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm'}, expectErr: errInvalidDNSName},
		{msg: []byte{1, 'a', 0xC0, 0}, expectErr: errPtrLoop},
		{msg: []byte{0b10000000}, expectErr: errInvalidDNSName},
		{msg: []byte{0b01000000}, expectErr: errInvalidDNSName},
	}

	for _, tt := range cases {
		var n Name
		offset, err := n.unpack(tt.msg, tt.nameStart)
		if err != tt.expectErr || offset != tt.expectOffset {
			t.Errorf(
				"Name.unpack(%v, %v) = (%v, %v); want = (%v, %v)",
				tt.msg, tt.nameStart, offset, err, tt.expectOffset, tt.expectErr,
			)
		}
		if err == nil {
			if n.Name != tt.expectName.Name || n.Length != tt.expectName.Length || n.Compression != tt.expectName.Compression {
				t.Errorf("Name.unpack(%v, %v) = %v, want = %v", tt.msg, tt.nameStart, n, tt.expectName)
			}
		}
	}
}

func TestUnpackNameCompressionPtrLoop(t *testing.T) {
	nb := nameBuilderState{}
	buf := make([]byte, headerLen, 1024)

	// This creates a 255b name with the maximum (sensible) pointer limit.
	for i := 3; i <= maxEncodedNameLen; i += 2 {
		name := make([]byte, maxEncodedNameLen)[:i]
		for j := 0; j < i-1; j += 2 {
			name[j] = 1
			name[j+1] = 'a'
		}
		buf, _ = nb.appendName(buf, math.MaxInt, 0, name, true)
		// append the longest name twice, so that it is also compressed directly.
		if len(name) == maxEncodedNameLen {
			buf, _ = nb.appendName(buf, math.MaxInt, 0, name, true)
		}
	}

	offset := headerLen

	for len(buf) != offset {
		var n Name
		off, err := n.unpack(buf, offset)
		if err != nil {
			t.Fatalf("failed to unpack name at offset: %v: %v", offset, err)
		}
		offset += int(off)
	}

	// Badly compressed name (Pointer to a Pointer).
	ptrToPtrNameOffset := len(buf)
	buf = appendUint16(buf, 0xC000|uint16(ptrToPtrNameOffset-2))
	var n Name
	_, err := n.unpack(buf, ptrToPtrNameOffset)
	if err != errPtrLoop {
		t.Fatalf("unexpected error while unpacking badly packed name (ptr to ptr): %v, expected: %v", err, errPtrLoop)
	}
}
