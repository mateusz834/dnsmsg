package dnsmsg

import (
	"bytes"
	"fmt"
	"testing"
)

var nameUnpackTests = []struct {
	name string

	msg       []byte
	nameStart uint16

	err    error
	offset uint8
	rawLen uint8
}{
	{name: "valid go.dev", msg: []byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0}, offset: 8, rawLen: 8},
	{name: "nameStart 2 valid go.dev", nameStart: 2, msg: []byte{32, 3, 2, 'g', 'o', 3, 'd', 'e', 'v', 0}, offset: 8, rawLen: 8},
	{name: "nameStart 2 junk after name valid go.dev", nameStart: 2, msg: []byte{32, 3, 2, 'g', 'o', 3, 'd', 'e', 'v', 0, 2, 66, 66, 0}, offset: 8, rawLen: 8},
	{name: "www.go.dev", msg: []byte{3, 'w', 'w', 'w', 2, 'g', 'o', 3, 'd', 'e', 'v', 0}, offset: 12, rawLen: 12},
	{name: "www.go.dev ptr forward", msg: []byte{3, 'w', 'w', 'w', 0xC0, 10, 2, 2, 1, 1, 2, 'g', 'o', 3, 'd', 'e', 'v', 0}, offset: 6, rawLen: 12},
	{name: "www.go.dev ptr forward with junk", nameStart: 3, msg: []byte{2, 1, 1, 3, 'w', 'w', 'w', 0xC0, 13, 2, 2, 1, 1, 2, 'g', 'o', 3, 'd', 'e', 'v', 0, 2, 22, 33}, offset: 6, rawLen: 12},
	{name: "www.go.dev ptr backwards", nameStart: 11, msg: []byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0, 2, 1, 1, 3, 'w', 'w', 'w', 0xC0, 0}, offset: 6, rawLen: 12},
	{name: "www.go.dev ptr backwards with junk", nameStart: 14, msg: []byte{2, 1, 1, 2, 'g', 'o', 3, 'd', 'e', 'v', 0, 2, 1, 1, 3, 'w', 'w', 'w', 0xC0, 3, 2, 22, 22}, offset: 6, rawLen: 12},
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

			// +4 (pointer and random data in between")
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

			// +4 (pointer and random data in between")
			if len(buf) != 256+4 {
				panic("invalid name")
			}

			return buf
		}(),
		err: errInvalidDNSName,
	},

	{name: "smaller name than label length", msg: []byte{3, 'w', 'w', 'w', 2, 'g', 'o', 5, 'd', 'e', 'v', 0}, err: errInvalidDNSName},
	{name: "missing root label", msg: []byte{3, 'w', 'w', 'w', 2, 'g', 'o', 3, 'd', 'e', 'v'}, err: errInvalidDNSName},
	{name: "pointer loop 1", msg: []byte{3, 'w', 'w', 'w', 0xC0, 0}, err: errPtrLoop},
	{name: "pointer loop 2", nameStart: 2, msg: []byte{32, 32, 0xC0, 2, 32}, err: errPtrLoop},
	{name: "reserved label bit 2", msg: []byte{0b10000000}, err: errInvalidDNSName},
	{name: "reserved label bit 1", msg: []byte{0b01000000}, err: errInvalidDNSName},
}

func TestParserNameUnpack(t *testing.T) {
	for _, v := range nameUnpackTests {
		t.Run(v.name, func(t *testing.T) {
			msg, err := NewParser(v.msg)
			if err != nil {
				t.Fatalf("unexpected NewParser() error: %v", err)
			}

			m := ParserName{m: &msg, nameStart: v.nameStart}

			offset, err := m.unpack()
			if err != v.err {
				t.Fatalf("got err: %v, expected: %v", err, v.err)
			}

			if offset != uint16(v.offset) {
				t.Fatalf("got offset: %v, expected: %v", offset, v.offset)
			}

			if rawLen := m.RawLen(); rawLen != v.rawLen {
				t.Fatalf("got RawLen: %v, expected: %v", v.rawLen, rawLen)
			}
		})
	}
}

func FuzzParserNameUnpack(f *testing.F) {
	for _, v := range nameUnpackTests {
		f.Add(v.nameStart, v.msg)
	}
	f.Fuzz(func(_ *testing.T, nameStart uint16, buf []byte) {
		msg, err := NewParser(buf)
		if err != nil {
			return
		}
		m := ParserName{m: &msg, nameStart: nameStart}
		m.unpack()
	})
}

func prepNameSameMsg(buf []byte, n1Start, n2Start uint16) [2]ParserName {
	msg, err := NewParser(buf)
	if err != nil {
		panic(err)
	}

	m1 := ParserName{m: &msg, nameStart: n1Start}
	_, err = m1.unpack()
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

func prepNameDifferentMsg(buf1, buf2 []byte, n1Start, n2Start uint16) [2]ParserName {
	msg1, err := NewParser(buf1)
	if err != nil {
		panic(err)
	}

	msg2, err := NewParser(buf2)
	if err != nil {
		panic(err)
	}

	m1 := ParserName{m: &msg1, nameStart: n1Start}
	_, err = m1.unpack()
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
