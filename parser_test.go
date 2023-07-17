package dnsmsg

import (
	"bytes"
	"fmt"
	"testing"
)

func TestParserUnpackName(t *testing.T) {
	var tests = []struct {
		name string

		msg         []byte
		parseOffset int

		err    error
		offset uint8
		rawLen uint8
	}{
		{
			name:   "example.com",
			msg:    []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 1, 1, 0},
			offset: 13,
			rawLen: 13,
		},
		{
			name:        "example.com",
			parseOffset: 2,
			msg:         []byte{32, 8, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 1, 1, 0},
			offset:      13,
			rawLen:      13,
		},
		{
			name:   "www.example.com",
			msg:    []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 1, 1},
			offset: 17,
			rawLen: 17,
		},
		{
			name:        "www.example.com with compression ptr backwards",
			parseOffset: 16,
			msg:         []byte{8, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 1, 1, 3, 'w', 'w', 'w', 0xC0, 1},
			offset:      6,
			rawLen:      17,
		},
		{
			name:        "www.example.com with compression ptr forwards",
			parseOffset: 1,
			msg:         []byte{4, 3, 'w', 'w', 'w', 0xC0, 8, 8, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 1, 1},
			offset:      6,
			rawLen:      17,
		},
		{
			name: "255B",
			msg: func() []byte {
				var buf []byte
				a63 := bytes.Repeat([]byte{'a'}, 63)
				a61 := bytes.Repeat([]byte{'a'}, 61)

				for i := 0; i < 3; i++ {
					buf = append(buf, byte(len(a63)))
					buf = append(buf, a63...)
				}

				buf = append(buf, byte(len(a61)))
				buf = append(buf, a61...)
				buf = append(buf, 0)

				if len(buf) != 255 {
					panic("invalid name")
				}

				return buf
			}(),
			offset: 255,
			rawLen: 255,
		},
		{
			name: "255B with one compression pointer",
			msg: func() []byte {
				var buf []byte
				a63 := bytes.Repeat([]byte{'a'}, 63)
				z61 := bytes.Repeat([]byte{'z'}, 61)

				buf = append(buf, byte(len(z61)))
				buf = append(buf, z61...)
				buf = append(buf, 0xC0, byte(len(buf))+4)

				buf = append(buf, 32, 32) // random data

				for i := 0; i < 3; i++ {
					buf = append(buf, byte(len(a63)))
					buf = append(buf, a63...)
				}
				buf = append(buf, 0)

				// +4 (pointer and random data in-between")
				if len(buf) != 255+4 {
					panic("invalid name")
				}

				return buf
			}(),
			offset: 64,
			rawLen: 255,
		},
		{
			name: "256B",
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
			err: errInvalidDNSName,
		},
		{
			name: "256B with one compression pointer",
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
			err: errInvalidDNSName,
		},

		{name: "smaller name than label length", msg: []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 5, 'c', 'o', 'm', 0}, err: errInvalidDNSName},
		{name: "missing root label", msg: []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm'}, err: errInvalidDNSName},
		{name: "pointer loop", msg: []byte{1, 'a', 0xC0, 0}, err: errPtrLoop},
		{name: "reserved label bit(8) ", msg: []byte{0b10000000}, err: errInvalidDNSName},
		{name: "reserved label bit(7)", msg: []byte{0b01000000}, err: errInvalidDNSName},
	}

	for _, v := range tests {
		msg := Parser{msg: v.msg}
		n, offset, err := msg.unpackName(v.parseOffset)
		if err != v.err {
			t.Fatalf("%v: got err: %v, expected: %v", v.name, err, v.err)
		}

		if offset != uint16(v.offset) {
			t.Fatalf("%v: got offset: %v, expected: %v", v.name, offset, v.offset)
		}

		if rawLen := n.RawLen(); rawLen != v.rawLen {
			t.Fatalf("%v: got RawLen: %v, expected: %v", v.name, v.rawLen, rawLen)
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
		buf = nb.appendName(buf, 0, name, true)
		// append the longest name twice, so that it is also compressed directly.
		if len(name) == maxEncodedNameLen {
			buf = nb.appendName(buf, 0, name, true)
		}
	}

	p := Parser{msg: buf}
	offset := headerLen

	for len(buf) != offset {
		_, n, err := p.unpackName(offset)
		if err != nil {
			t.Fatalf("failed to unpack name at offset: %v: %v", offset, err)
		}
		offset += int(n)
	}

	// Badly compressed name (Pointer to a Pointer).
	ptrToPtrNameOffset := len(buf)
	buf = appendUint16(buf, 0xC000|uint16(ptrToPtrNameOffset-2))
	p = Parser{msg: buf}
	_, _, err := p.unpackName(ptrToPtrNameOffset)
	if err != errPtrLoop {
		t.Fatalf("unexpected error while unpacking badly packed name (ptr to ptr): %v, expected: %v", err, errPtrLoop)
	}

}

func prepNameSameMsg(buf []byte, n1Start, n2Start int) [2]ParserName {
	msg := Parser{msg: buf}

	m1 := ParserName{m: &msg, nameStart: n1Start}
	_, err := m1.unpack()
	if err != nil {
		panic(err)
	}

	m2 := ParserName{m: &msg, nameStart: n2Start}
	_, err = m2.unpack()
	if err != nil {
		panic(err)
	}

	var n [2]ParserName
	n[0] = m1
	n[1] = m2
	return n
}

func prepNameDifferentMsg(buf1, buf2 []byte, n1Start, n2Start int) [2]ParserName {
	msg1, msg2 := Parser{msg: buf1}, Parser{msg: buf2}

	m1 := ParserName{m: &msg1, nameStart: n1Start}
	_, err := m1.unpack()
	if err != nil {
		panic(err)
	}

	m2 := ParserName{m: &msg2, nameStart: n2Start}
	_, err = m2.unpack()
	if err != nil {
		panic(err)
	}

	var n [2]ParserName
	n[0] = m1
	n[1] = m2
	return n
}

var nameEqualTests = []struct {
	name string

	names [2]ParserName
	equal bool
}{
	{
		name: "(same msg) same nameStart",
		names: prepNameSameMsg([]byte{
			2, 'g', 'o', 3, 'd', 'e', 'v', 0,
		}, 0, 0),
		equal: true,
	},

	{
		name: "(same msg) second name directly points to first name",
		names: prepNameSameMsg([]byte{
			2, 'g', 'o', 3, 'd', 'e', 'v', 0,
			0xC0, 0,
		}, 0, 8),
		equal: true,
	},

	{
		name: "(same msg) two separate names, without compression pointers",
		names: prepNameSameMsg([]byte{
			2, 'g', 'o', 3, 'd', 'e', 'v', 0,
			2, 'g', 'o', 3, 'd', 'e', 'v', 0,
		}, 0, 8),
		equal: true,
	},

	{
		name: "(same msg) two separate names without compression pointers with different letter case",
		names: prepNameSameMsg([]byte{
			2, 'G', 'o', 3, 'd', 'E', 'V', 0,
			2, 'g', 'O', 3, 'D', 'e', 'V', 0,
		}, 0, 8),
		equal: true,
	},

	{
		name: "(same msg) two different names go.dev www.go.dev, no pointers",
		names: prepNameSameMsg([]byte{
			2, 'g', 'o', 3, 'd', 'e', 'v', 0,
			3, 'w', 'w', 'w', 2, 'g', 'o', 3, 'd', 'e', 'v', 0,
		}, 0, 8),
		equal: false,
	},

	{
		name: "(same msg) two different names go.dev go.go.dev, no pointers",
		names: prepNameSameMsg([]byte{
			2, 'g', 'o', 3, 'd', 'e', 'b', 0,
			2, 'g', 'o', 2, 'g', 'o', 3, 'd', 'e', 'v', 0,
		}, 0, 8),
		equal: false,
	},

	{
		name: "(same msg) two different names go.dev www.go.dev with pointers",
		names: prepNameSameMsg([]byte{
			2, 'G', 'o', 3, 'd', 'R', 'V', 0,
			3, 'w', 'w', 'w', 0xC0, 0,
		}, 0, 8),
		equal: false,
	},

	{
		name: "(different msgs) same name no pointers",
		names: prepNameDifferentMsg([]byte{
			2, 'g', 'o', 3, 'd', 'e', 'v', 0,
		}, []byte{
			2, 'g', 'o', 3, 'd', 'e', 'v', 0,
		}, 0, 0),
		equal: true,
	},

	{
		name: "(different msgs) same names, different letter case, no pointers",
		names: prepNameDifferentMsg([]byte{
			2, 'G', 'o', 3, 'd', 'E', 'V', 0,
		}, []byte{
			2, 'G', 'O', 3, 'D', 'e', 'v', 0,
		}, 0, 0),
		equal: true,
	},

	{
		name: "(different msgs) different names, no pointers",
		names: prepNameDifferentMsg([]byte{
			2, 'g', 'o', 3, 'd', 'e', 'v', 0,
		}, []byte{
			2, 'g', 'o', 2, 'g', 'o', 3, 'd', 'e', 'v', 0,
		}, 0, 0),
		equal: false,
	},

	{
		name: "(different msgs) same name with pointers",
		names: prepNameDifferentMsg([]byte{
			2, 'g', 'o', 3, 'd', 'e', 'v', 0,
		}, []byte{
			3, 'd', 'e', 'v', 0, 2, 'g', 'o', 0xC0, 0,
		}, 0, 5),
		equal: true,
	},

	{
		name: "(different msgs) different names with pointers",
		names: prepNameDifferentMsg([]byte{
			2, 'g', 'o', 3, 'd', 'e', 'v', 0,
		}, []byte{
			3, 'd', 'e', 'v', 0, 2, 'g', 'o', 2, 'g', 'o', 0xC0, 0,
		}, 0, 5),
		equal: false,
	},
}

func TestNameEqual(t *testing.T) {
	for i, v := range nameEqualTests {
		for ti, tv := range []string{"n[0].Equal(n[1])", "n[1].Equal(n[0])"} {
			prefix := fmt.Sprintf("%v: %v: %v:", i, v.name, tv)

			names := v.names
			if ti == 1 {
				names[0], names[1] = v.names[1], v.names[0]
			}

			if eq := names[0].Equal(&names[1]); eq != v.equal {
				t.Errorf("%v expected: %v, but: %v", prefix, v.equal, eq)
			}
		}
	}
}

func newParserName(buf []byte) ParserName {
	msg := Parser{msg: buf}
	m := ParserName{m: &msg, nameStart: 0}
	_, err := m.unpack()
	if err != nil {
		panic(err)
	}
	return m
}

func TestSearchNameEqual(t *testing.T) {
	n, err := NewSearchName(MustNewName("www"), MustNewName("go.dev"))
	if err != nil {
		t.Fatal(err)
	}

	n2, err := NewSearchName(Name{}, MustNewName("www.go.dev"))
	if err != nil {
		t.Fatal(err)
	}

	m := newParserName([]byte{3, 'w', 'w', 'w', 2, 'g', 'o', 3, 'd', 'e', 'v', 0})

	if !m.EqualSearchName(n) {
		t.Fatal("names are not equal")
	}

	if m.nameStart != 0 {
		t.Fatal("nameStart has changed")
	}

	if !m.EqualSearchName(n2) {
		t.Fatal("names are not equal")
	}

	m = newParserName([]byte{3, 'w', 'w', 'w', 0})
	if m.EqualSearchName(n) {
		t.Fatal("names are equal")
	}
}

func FuzzParser(f *testing.F) {
	b := StartBuilder(nil, 0, 0)
	b.Question(Question[RawName]{
		Name:  MustNewRawName("example.com"),
		Type:  TypeA,
		Class: ClassIN,
	})
	b.StartAnswers()
	b.ResourceA(ResourceHeader[RawName]{
		Name:  MustNewRawName("example.com"),
		Type:  TypeA,
		Class: ClassIN,
		TTL:   60,
	}, ResourceA{A: [4]byte{192, 0, 2, 1}})
	f.Add(b.Bytes())

	f.Fuzz(func(t *testing.T, msg []byte) {
		p, hdr, err := Parse(msg)
		if err != nil {
			return
		}

		for count := 0; ; count++ {
			_, err := p.Question()
			if err != nil {
				if err == errInvalidOperation {
					t.Fatalf("unexpected %v error", errInvalidOperation)
				}
				if err == ErrSectionDone {
					if count != int(hdr.QDCount) {
						t.Errorf("unexpected amount of questions, got: %v, expected: %v", count, hdr.QDCount)
					}
					break
				}
				return
			}
		}

		expectCounts := []uint16{hdr.ANCount, hdr.NSCount, hdr.ARCount}
		for i, nextSection := range []func() error{p.StartAnswers, p.StartAuthorities, p.StartAdditionals} {
			if err := nextSection(); err != nil {
				t.Fatalf("failed while changing parsing section: %v", err)
			}

			for count := 0; ; count++ {
				hdr, err := p.ResourceHeader()
				if err != nil {
					if err == errInvalidOperation {
						t.Fatalf("unexpected %v error", errInvalidOperation)
					}
					if err == ErrSectionDone {
						if count != int(expectCounts[i]) {
							t.Errorf("unexpected amount of resources, got: %v, expected: %v", count, expectCounts[i])
						}
						break
					}
					return
				}

				switch hdr.Type {
				case TypeA:
					_, err = p.ResourceA()
				case TypeAAAA:
					_, err = p.ResourceAAAA()
				case TypeCNAME:
					_, err = p.ResourceCNAME()
				case TypeMX:
					_, err = p.ResourceMX()
				case TypeTXT:
					var txt RawResourceTXT
					txt, err = p.RawResourceTXT()
					txt.ToResourceTXT()
				default:
					err = p.SkipResourceData()
				}

				if err != nil {
					if err == errInvalidOperation {
						t.Fatalf("unexpected %v error", errInvalidOperation)
					}
					return
				}
			}
		}

		if err := p.End(); err != nil {
			if err == errInvalidOperation {
				t.Fatalf("unexpected %v error", errInvalidOperation)
			}
			return
		}
	})
}
