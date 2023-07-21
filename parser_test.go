package dnsmsg

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
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

func TestParserNameEqual(t *testing.T) {
	prepNamesSameMsg := func(t *testing.T, buf []byte, n1Start, n2Start int) [2]ParserName {
		msg := Parser{msg: buf}
		m1, _, err := msg.unpackName(n1Start)
		if err != nil {
			t.Fatal(err)
		}
		m2, _, err := msg.unpackName(n2Start)
		if err != nil {
			t.Fatal(err)
		}
		ret := [2]ParserName{m1, m2}
		return ret
	}

	prepNamesDifferentMsg := func(t *testing.T, buf1, buf2 []byte, n1Start, n2Start int) [2]ParserName {
		msg1, msg2 := Parser{msg: buf1}, Parser{msg: buf2}
		m1, _, err := msg1.unpackName(n1Start)
		if err != nil {
			t.Fatal(err)
		}
		m2, _, err := msg2.unpackName(n2Start)
		if err != nil {
			t.Fatal(err)
		}
		ret := [2]ParserName{m1, m2}
		return ret
	}

	var tests = []struct {
		name string

		names [2]ParserName
		equal bool
	}{
		{
			name: "(same msg) same nameStart",
			names: prepNamesSameMsg(t, []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
			}, 0, 0),
			equal: true,
		},

		{
			name: "(same msg) second name directly points to first name",
			names: prepNamesSameMsg(t, []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
				0xC0, 0,
			}, 0, 13),
			equal: true,
		},

		{
			name: "(same msg) two separate names, without compression pointers",
			names: prepNamesSameMsg(t, []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
			}, 0, 13),
			equal: true,
		},

		{
			name: "(same msg) two separate names without compression pointers with different letter case",
			names: prepNamesSameMsg(t, []byte{
				7, 'E', 'x', 'A', 'm', 'P', 'l', 'e', 3, 'c', 'O', 'M', 0,
				7, 'E', 'X', 'a', 'm', 'P', 'l', 'E', 3, 'c', 'o', 'm', 0,
			}, 0, 13),
			equal: true,
		},

		{
			name: "(same msg) two different names example.com != www.example.com, no pointers",
			names: prepNamesSameMsg(t, []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
				3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
			}, 0, 13),
			equal: false,
		},

		{
			name: "(same msg) two different names ttt.example.com != www.example.com, no pointers",
			names: prepNamesSameMsg(t, []byte{
				3, 't', 't', 't', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
				3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
			}, 0, 17),
			equal: false,
		},

		{
			name: "(same msg) two different names example.com != www.example.com, with pointers",
			names: prepNamesSameMsg(t, []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
				3, 'w', 'w', 'w', 0xC0, 0,
			}, 0, 13),
			equal: false,
		},

		{
			name: "(same msg) two different names example.com == example.com, with multiple pointers",
			names: prepNamesSameMsg(t, []byte{
				0xC0, 3, 99, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
				0xC0, 0,
			}, 0, 16),
			equal: true,
		},

		{
			name: "(different msgs) same name, no pointers",
			names: prepNamesDifferentMsg(t, []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
			}, []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
			}, 0, 0),
			equal: true,
		},

		{
			name: "(different msgs) same names, different letter case, no pointers",
			names: prepNamesDifferentMsg(t, []byte{
				7, 'E', 'x', 'a', 'M', 'P', 'l', 'e', 3, 'c', 'O', 'm', 0,
			}, []byte{
				7, 'E', 'X', 'a', 'm', 'P', 'l', 'E', 3, 'c', 'o', 'm', 0,
			}, 0, 0),
			equal: true,
		},

		{
			name: "(different msgs) different names, no pointers",
			names: prepNamesDifferentMsg(t, []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
			}, []byte{
				3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
			}, 0, 0),
			equal: false,
		},

		{
			name: "(different msgs) same names, with pointers",
			names: prepNamesDifferentMsg(t, []byte{
				3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
			}, []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 3, 'w', 'w', 'w', 0xC0, 0,
			}, 0, 13),
			equal: true,
		},

		{
			name: "(different msgs) different names, with pointers",
			names: prepNamesDifferentMsg(t, []byte{
				3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
			}, []byte{
				3, 't', 't', 't', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 3, 'w', 'w', 'w', 0xC0, 0,
			}, 0, 17),
			equal: false,
		},
	}

	for i, v := range tests {
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

func TestParserNameEqualToStringName(t *testing.T) {
	newParserName := func(t *testing.T, buf []byte, offset int) ParserName {
		msg := Parser{msg: buf}
		m, _, err := msg.unpackName(offset)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}

	newSearchName := func(t *testing.T, n, n2 Name) SearchName {
		s, err := NewSearchName(n, n2)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	tests := []struct {
		parserName  ParserName
		name        Name
		searchNames []SearchName
		equal       bool
	}{
		{
			parserName:  newParserName(t, []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}, 0),
			name:        MustNewName("example.com"),
			searchNames: []SearchName{newSearchName(t, MustNewName("example"), MustNewName("com"))},
			equal:       true,
		},
		{
			parserName:  newParserName(t, []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}, 0),
			name:        MustNewName("example.com."),
			searchNames: []SearchName{newSearchName(t, MustNewName("example"), MustNewName("com."))},
			equal:       true,
		},
		{
			parserName: newParserName(t, []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}, 0),
			name:       MustNewName("www.example.com"),
			searchNames: []SearchName{
				newSearchName(t, MustNewName("www"), MustNewName("example.com")),
				newSearchName(t, MustNewName("www.example"), MustNewName("com")),
			},
			equal: false,
		},
		{
			parserName:  newParserName(t, []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}, 0),
			name:        MustNewName("example.com"),
			searchNames: []SearchName{newSearchName(t, MustNewName("example"), MustNewName("com"))},
			equal:       false,
		},
		{
			parserName:  newParserName(t, []byte{7, 'E', 'X', 'A', 'M', 'p', 'l', 'E', 3, 'c', 'o', 'm', 0}, 0),
			name:        MustNewName("eXAmPle.com"),
			searchNames: []SearchName{newSearchName(t, MustNewName("eXAmPle"), MustNewName("com"))},
			equal:       true,
		},
		{
			parserName: newParserName(t, []byte{7, 'E', 'X', 'A', 'M', 'p', 'l', 'E', 3, 'c', 'o', 'm', 0}, 0),
			name:       MustNewName("eXAmPle.com."),
			searchNames: []SearchName{
				newSearchName(t, Name{}, MustNewName("eXAmPle.com")),
				newSearchName(t, MustNewName("eXAmPle"), MustNewName("com")),
			},
			equal: true,
		},
		{
			parserName:  newParserName(t, []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}, 0),
			name:        MustNewName("\\exam\\ple.c\\om"),
			searchNames: []SearchName{newSearchName(t, MustNewName("\\exam\\ple"), MustNewName("c\\om"))},
			equal:       true,
		},
		{
			parserName:  newParserName(t, []byte{3, 33, 99, 'z', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}, 0),
			name:        MustNewName("\\033\\099\\" + strconv.Itoa('z') + ".example.com"),
			searchNames: []SearchName{newSearchName(t, MustNewName("\\033\\099\\"+strconv.Itoa('z')), MustNewName("example.com"))},
			equal:       true,
		},
		{
			parserName:  newParserName(t, []byte{3, 0x33, 0x99, 'z', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}, 0),
			name:        MustNewName("\x33\x99\\z.example.com"),
			searchNames: []SearchName{newSearchName(t, MustNewName("\x33\x99\\"+strconv.Itoa('z')), MustNewName("example.com"))},
			equal:       true,
		},
		{
			parserName:  newParserName(t, []byte{3, 'w', 'w', '.', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}, 0),
			name:        MustNewName("ww\\..example.com"),
			searchNames: []SearchName{newSearchName(t, MustNewName("ww\\."), MustNewName("example.com"))},
			equal:       true,
		},
		{
			parserName: newParserName(t, []byte{3, 'w', 'w', '.', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}, 0),
			name:       MustNewName("ww\\.example.com"),
			equal:      false,
		},
		{
			parserName: newParserName(t, []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 2, 3, 'w', 'w', 'w', 0xC0, 0}, 14),
			name:       MustNewName("www.example.com"),
			searchNames: []SearchName{
				newSearchName(t, MustNewName("www"), MustNewName("example.com")),
				newSearchName(t, MustNewName("www.example"), MustNewName("com")),
			},
			equal: true,
		},
		{
			parserName: newParserName(t, []byte{0xC0, 3, 9, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 2, 3, 'w', 'w', 'w', 0xC0, 0}, 17),
			name:       MustNewName("www.example.com"),
			searchNames: []SearchName{
				newSearchName(t, MustNewName("www"), MustNewName("example.com")),
				newSearchName(t, MustNewName("www.example"), MustNewName("com")),
			},
			equal: true,
		},
	}

	for _, v := range tests {
		eq := v.parserName.EqualName(v.name)
		if eq != v.equal {
			t.Errorf("ParserName(%#v) == Name(%#v) = %v", v.parserName.String(), v.name.String(), eq)
		}

		for _, vv := range append(v.searchNames, newSearchName(t, Name{}, v.name)) {
			eq := v.parserName.EqualSearchName(vv)
			if eq != v.equal {
				t.Errorf("ParserName(%#v) == %#v = %v", v.parserName.String(), vv, eq)
			}
		}
	}
}

func TestParse(t *testing.T) {
	expect := Header{
		ID:      43127,
		Flags:   Flags(12930),
		QDCount: 49840,
		ANCount: 55119,
		NSCount: 33990,
		ARCount: 62101,
	}

	raw := binary.BigEndian.AppendUint16(make([]byte, 0, 12), expect.ID)
	raw = binary.BigEndian.AppendUint16(raw, uint16(expect.Flags))
	raw = binary.BigEndian.AppendUint16(raw, expect.QDCount)
	raw = binary.BigEndian.AppendUint16(raw, expect.ANCount)
	raw = binary.BigEndian.AppendUint16(raw, expect.NSCount)
	raw = binary.BigEndian.AppendUint16(raw, expect.ARCount)

	p, hdr, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	if hdr != expect {
		t.Fatalf("Parse returned header: %#v, expected: %#v", hdr, expect)
	}

	_, err = p.Question()
	if err != errInvalidDNSName {
		t.Fatalf("unexpected error: %v", err)
	}

	_, _, err = Parse(raw[:11])
	if err == nil {
		t.Fatal("unexpected success while parsing too short dns message")
	}
}

func TestParseQuestion(t *testing.T) {
	raw := binary.BigEndian.AppendUint16(make([]byte, 0, 12), 0)
	raw = binary.BigEndian.AppendUint16(raw, 0)
	raw = binary.BigEndian.AppendUint16(raw, 2)
	raw = binary.BigEndian.AppendUint16(raw, 0)
	raw = binary.BigEndian.AppendUint16(raw, 0)
	raw = binary.BigEndian.AppendUint16(raw, 0)

	raw = append(raw, []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}...)
	raw = binary.BigEndian.AppendUint16(raw, 1)
	raw = binary.BigEndian.AppendUint16(raw, 1)

	raw = append(raw, []byte{3, 'w', 'w', 'w', 0xC0, 12}...)
	raw = binary.BigEndian.AppendUint16(raw, 1)
	raw = binary.BigEndian.AppendUint16(raw, 1)

	p, hdr, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	expect := Header{QDCount: 2}
	if hdr != expect {
		t.Fatalf("Parse returned header: %#v, expected: %#v", hdr, expect)
	}

	q1, err := p.Question()
	if err != nil {
		t.Fatal(err)
	}

	if !q1.Name.EqualName(MustNewName("example.com")) {
		t.Errorf("name from question is not equal to example.com")
	}

	if q1.Type != TypeA {
		t.Errorf("type is not equal to TypeA")
	}

	if q1.Class != ClassIN {
		t.Errorf("class is not equal to ClassIN")
	}

	q2, err := p.Question()
	if err != nil {
		t.Fatal(err)
	}

	if !q2.Name.EqualName(MustNewName("www.example.com")) {
		t.Errorf("name from question is not equal to www.example.com")
	}

	if q2.Type != TypeA {
		t.Errorf("type is not equal to TypeA")
	}

	if q2.Class != ClassIN {
		t.Errorf("class is not equal to ClassIN")
	}

	_, err = p.Question()
	if err != ErrSectionDone {
		t.Fatalf("unexpected error after parsing all questions: %v, expected: %v", err, ErrSectionDone)
	}

	if err := p.End(); err != nil {
		t.Fatal(err)
	}

	err = p.SkipQuestions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParserInvalidOperation(t *testing.T) {
	b := StartBuilder(make([]byte, 0, 512), 0, 0)

	b.Question(Question[RawName]{
		Name:  MustNewRawName("example.com"),
		Type:  TypeA,
		Class: ClassIN,
	})

	for _, nextSection := range []func(){b.StartAnswers, b.StartAuthorities, b.StartAdditionals} {
		nextSection()
		hdr := ResourceHeader[RawName]{
			Name:  MustNewRawName("example.com"),
			Class: ClassIN,
			TTL:   60,
		}
		hdr.Type = TypeA
		b.ResourceA(hdr, ResourceA{A: [4]byte{192, 0, 2, 1}})
		hdr.Type = TypeAAAA
		b.ResourceAAAA(hdr, ResourceAAAA{AAAA: netip.MustParseAddr("2001:db8::1").As16()})
		hdr.Type = TypeTXT
		b.ResourceTXT(hdr, ResourceTXT{TXT: [][]byte{[]byte("test"), []byte("test2")}})
		b.RawResourceTXT(hdr, RawResourceTXT{[]byte{1, 'a', 2, 'b', 'a'}})
		hdr.Type = TypeCNAME
		b.ResourceCNAME(hdr, ResourceCNAME[RawName]{CNAME: MustNewRawName("www.example.com")})
		hdr.Type = TypeMX
		b.ResourceMX(hdr, ResourceMX[RawName]{Pref: 100, MX: MustNewRawName("smtp.example.com")})
	}

	p, hdr, err := Parse(b.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	knownResourceTypes := []Type{TypeA, TypeAAAA, TypeTXT, TypeCNAME, TypeMX}
	parseResource := func(p *Parser, resType Type) error {
		switch resType {
		case TypeA:
			_, err = p.ResourceA()
		case TypeAAAA:
			_, err = p.ResourceAAAA()
		case TypeTXT:
			_, err = p.RawResourceTXT()
		case TypeCNAME:
			_, err = p.ResourceCNAME()
		case TypeMX:
			_, err = p.ResourceMX()
		default:
			panic("unknown resource")
		}
		return err
	}

	if err := p.SkipResources(); err != errInvalidOperation {
		t.Fatalf("unexpected error while skipping all resources: %v, want %v", err, errInvalidOperation)
	}

	if err := p.SkipResourceData(); err != errInvalidOperation {
		t.Fatalf("unexpected error while skipping resource data: %v, want %v", err, errInvalidOperation)
	}

	for _, tt := range knownResourceTypes {
		if err := parseResource(&p, tt); err != errInvalidOperation {
			t.Fatalf("unexpected error while using resource parsing data methods: %v, want %v", err, errInvalidOperation)
		}
	}

	for _, next := range []func() error{p.StartAnswers, p.StartAuthorities, p.StartAdditionals} {
		if err := next(); err != errInvalidOperation {
			t.Fatalf("unexpected error while changing parsing section: %v, want %v", err, errInvalidOperation)
		}
	}

	_, err = p.Question()
	if err != nil {
		t.Fatal(err)
	}

	if err := p.SkipResources(); err != errInvalidOperation {
		t.Fatalf("unexpected error while skipping all resources: %v, want %v", err, errInvalidOperation)
	}

	if err := p.SkipResourceData(); err != errInvalidOperation {
		t.Fatalf("unexpected error while skipping resource data: %v, want %v", err, errInvalidOperation)
	}

	for _, tt := range knownResourceTypes {
		if err := parseResource(&p, tt); err != errInvalidOperation {
			t.Fatalf("unexpected error while using resource parsing data methods: %v, want %v", err, errInvalidOperation)
		}
	}

	for _, next := range []func() error{p.StartAuthorities, p.StartAdditionals} {
		if err := next(); err != errInvalidOperation {
			t.Fatalf("unexpected error while changing parsing section: %v, want %v", err, errInvalidOperation)
		}
	}

	expectCounts := []uint16{hdr.ANCount, hdr.NSCount, hdr.ARCount}
	changeSections := []func() error{p.StartAnswers, p.StartAuthorities, p.StartAdditionals}
	for curSection, nextSection := range changeSections {
		if err := nextSection(); err != nil {
			t.Fatal(err)
		}

		for count := expectCounts[curSection]; ; count-- {
			if _, err := p.Question(); err != errInvalidOperation {
				t.Fatalf("unexpected error while trying to parse question: %v, want %v", err, errInvalidOperation)
			}

			if err := p.SkipQuestions(); err != errInvalidOperation {
				t.Fatalf("unexpected error while trying to skip all questions: %v, want %v", err, errInvalidOperation)
			}

			invalidChangeSection := changeSections
			if count == 0 {
				switch curSection {
				case 0:
					invalidChangeSection = []func() error{p.StartAnswers, p.StartAdditionals}
				case 1:
					invalidChangeSection = []func() error{p.StartAnswers, p.StartAuthorities}
				}
			}

			for _, next := range invalidChangeSection {
				if err := next(); err != errInvalidOperation {
					t.Fatalf("unexpected error while changing parsing section: %v, want %v", err, errInvalidOperation)
				}
			}

			if err := p.SkipResourceData(); err != errInvalidOperation {
				t.Fatalf("unexpected error while skipping resource data: %v, want %v", err, errInvalidOperation)
			}

			for _, tt := range knownResourceTypes {
				if err := parseResource(&p, tt); err != errInvalidOperation {
					t.Fatalf("unexpected error while using resource parsing data methods: %v, want %v", err, errInvalidOperation)
				}
			}

			rhdr, err := p.ResourceHeader()
			if err != nil {
				if err == ErrSectionDone {
					break
				}
				t.Fatal(err)
			}

			if _, err := p.Question(); err != errInvalidOperation {
				t.Fatalf("unexpected error while trying to parse question: %v, want %v", err, errInvalidOperation)
			}

			if err := p.SkipQuestions(); err != errInvalidOperation {
				t.Fatalf("unexpected error while trying to skip all questions: %v, want %v", err, errInvalidOperation)
			}

			for _, next := range changeSections {
				if err := next(); err != errInvalidOperation {
					t.Fatalf("unexpected error while changing parsing section: %v, want %v", err, errInvalidOperation)
				}
			}

			for _, tt := range knownResourceTypes {
				if rhdr.Type != tt {
					if err := parseResource(&p, tt); err != errInvalidOperation {
						t.Fatalf("unexpected error while using resource parsing data method: %v, want %v", err, errInvalidOperation)
					}
				}
			}

			if err := parseResource(&p, rhdr.Type); err != nil {
				t.Fatal(err)
			}
		}
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
	f.Add(b.Bytes(), false, false, false, false, 100)

	f.Fuzz(func(t *testing.T, msg []byte, skipQuestions, skipAnswers, skipAuthorities, skipAddtionals bool, skipRData int) {
		p, hdr, err := Parse(msg)
		if err != nil {
			return
		}

		if skipQuestions {
			err := p.SkipQuestions()
			if err != nil {
				if err == errInvalidOperation {
					t.Fatalf("unexpected %v error", errInvalidOperation)
				}
				return
			}
			hdr.QDCount = 0
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
					if _, err := p.Question(); err != ErrSectionDone {
						t.Fatalf("unexpected error: %v, expected: %v", err, ErrSectionDone)
					}
					break
				}
				return
			}
		}

		skipAll := []bool{skipAnswers, skipAuthorities, skipAddtionals}
		expectCounts := []uint16{hdr.ANCount, hdr.NSCount, hdr.ARCount}
		for i, nextSection := range []func() error{p.StartAnswers, p.StartAuthorities, p.StartAdditionals} {
			if err := nextSection(); err != nil {
				t.Fatalf("failed while changing parsing section: %v", err)
			}

			if skipAll[i] {
				err := p.SkipResources()
				if err != nil {
					if err == errInvalidOperation {
						t.Fatalf("unexpected %v error", errInvalidOperation)
					}
					return
				}
				expectCounts[i] = 0
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
						if _, err := p.ResourceHeader(); err != ErrSectionDone {
							t.Fatalf("unexpected error: %v, expected: %v", err, ErrSectionDone)
						}
						break
					}
					return
				}

				if count == skipRData {
					skipRData += skipRData / 2
					err = p.SkipResourceData()
				} else {
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
