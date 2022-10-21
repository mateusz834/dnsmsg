package dnsmsg

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

var (
	testHeader = Header{
		ID:      51128,
		Flags:   Flags(41025),
		QDCount: 11111,
		ANCount: 42224,
		NSCount: 33338,
		ARCount: 21025,
	}

	testHeaderRaw = func() []byte {
		var raw []byte
		raw = binary.BigEndian.AppendUint16(raw, testHeader.ID)
		raw = binary.BigEndian.AppendUint16(raw, uint16(testHeader.Flags))
		raw = binary.BigEndian.AppendUint16(raw, testHeader.QDCount)
		raw = binary.BigEndian.AppendUint16(raw, testHeader.ANCount)
		raw = binary.BigEndian.AppendUint16(raw, testHeader.NSCount)
		raw = binary.BigEndian.AppendUint16(raw, testHeader.ARCount)
		return raw
	}()
)

var hdr Header

func BenchmarkHeader(b *testing.B) {
	m, _ := NewMsg(testHeaderRaw)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.SetOffset(0)
		hdr, _ = m.Header()
	}
}

func TestHeader(t *testing.T) {
	m, err := NewMsg(testHeaderRaw)
	if err != nil {
		t.Fatal(err)
	}

	hdr, err := m.Header()
	if err != nil {
		t.Fatal(err)
	}

	if hdr != testHeader {
		t.Fatalf("got: %#v, expected %#v", hdr, testHeader)
	}

	if m.GetOffset() != 12 {
		t.Fatal("wrong offset after call to Header()")
	}
}

func TestHeaderErr(t *testing.T) {
	m, err := NewMsg(testHeaderRaw[:len(testHeaderRaw)-1])
	if err != nil {
		t.Fatal(err)
	}

	hdr, err := m.Header()
	if err != errInvalidDNSMessage {
		t.Fatalf("unexpected error, expected %v, but got %v", errInvalidDNSMessage, err)
	}

	var zero Header
	if hdr != zero {
		t.Fatalf("expected zero value of Header{}, but got %#v", hdr)
	}

	if m.GetOffset() != 0 {
		t.Fatal("wrong offset after call to Header()")
	}
}

var resourceHeaderTests = []struct {
	msg []byte
	hdr ResourceHeader[MsgRawName]

	err    error
	offset uint16
}{
	{
		msg: func() []byte {
			raw := []byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0}
			raw = binary.BigEndian.AppendUint16(raw, uint16(TypeA))
			raw = binary.BigEndian.AppendUint16(raw, uint16(ClassIN))
			raw = binary.BigEndian.AppendUint32(raw, 11111111)
			raw = binary.BigEndian.AppendUint16(raw, 1025)
			return raw
		}(),
		hdr: ResourceHeader[MsgRawName]{
			Name:   newMsgRawName([]byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0}),
			Type:   TypeA,
			Class:  ClassIN,
			TTL:    11111111,
			Length: 1025,
		},
		offset: 18,
	},

	{
		msg: func() []byte {
			raw := []byte{2, 'g', 'o', 0xC0, 15}
			raw = binary.BigEndian.AppendUint16(raw, uint16(TypeA))
			raw = binary.BigEndian.AppendUint16(raw, uint16(ClassIN))
			raw = binary.BigEndian.AppendUint32(raw, 11111111)
			raw = binary.BigEndian.AppendUint16(raw, 1025)
			raw = append(raw, []byte{3, 'd', 'e', 'v', 0}...)
			return raw
		}(),
		hdr: ResourceHeader[MsgRawName]{
			Name:   newMsgRawName([]byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0}),
			Type:   TypeA,
			Class:  ClassIN,
			TTL:    11111111,
			Length: 1025,
		},
		offset: 15,
	},

	{
		msg: func() []byte {
			raw := []byte{2, 'g', 'o', 0xC0, 32}
			raw = binary.BigEndian.AppendUint16(raw, uint16(TypeA))
			raw = binary.BigEndian.AppendUint16(raw, uint16(ClassIN))
			raw = binary.BigEndian.AppendUint32(raw, 11111111)
			raw = binary.BigEndian.AppendUint16(raw, 1025)
			return raw
		}(),
		err: errInvalidDNSName,
	},

	{
		msg: func() []byte {
			raw := []byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0}
			raw = binary.BigEndian.AppendUint16(raw, uint16(TypeA))
			raw = binary.BigEndian.AppendUint16(raw, uint16(ClassIN))
			raw = binary.BigEndian.AppendUint32(raw, 11111111)
			raw = binary.BigEndian.AppendUint16(raw, 1025)
			return raw[:len(raw)-1]
		}(),
		err: errInvalidDNSMessage,
	},
}

func TestResourceHeader(t *testing.T) {
	for i, v := range resourceHeaderTests {
		prefix := fmt.Sprintf("%v: %v: ", i, v.msg)

		msg, err := NewMsg(v.msg)
		if err != nil {
			t.Errorf("%v unexpected NewMsg error: %v", prefix, err)
			continue
		}

		rh, err := msg.ResourceHeader()
		if err != v.err {
			t.Errorf("%v expected error: %v, but got: %v", prefix, v.err, err)
		}

		if err != nil {
			if off := msg.GetOffset(); off != 0 {
				t.Errorf("%v returned error, so offset should not change (expected 0), but got %v", prefix, off)
			}
			continue
		}

		if !(rh.Name.Equal(&rh.Name) && rh.Type == v.hdr.Type && rh.Class == v.hdr.Class && rh.TTL == v.hdr.TTL && rh.Length == v.hdr.Length) {
			expect := fmt.Sprintf("{Name: %v, Type: %v, Class: %v, TTL: %v, Length: %v}", v.hdr.Name, v.hdr.Type, v.hdr.Class, v.hdr.TTL, v.hdr.Length)
			got := fmt.Sprintf("{Name: %v, Type: %v, Class: %v, TTL: %v, Length: %v}", rh.Name, rh.Type, rh.Class, rh.TTL, rh.Length)
			t.Errorf("%v expected: %v, but got: %v", prefix, expect, got)
		}

		if off := msg.GetOffset(); off != v.offset {
			t.Errorf("%v expected offset: %v, but got: %v", prefix, v.offset, off)
		}
	}
}

var questionTests = []struct {
	msg []byte
	q   Question[MsgRawName]

	err    error
	offset uint16
}{
	{
		msg: func() []byte {
			raw := []byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0}
			raw = binary.BigEndian.AppendUint16(raw, uint16(TypeA))
			raw = binary.BigEndian.AppendUint16(raw, uint16(ClassIN))
			return raw
		}(),
		q: Question[MsgRawName]{
			Name:  newMsgRawName([]byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0}),
			Type:  TypeA,
			Class: ClassIN,
		},
		offset: 12,
	},

	{
		msg: func() []byte {
			raw := []byte{2, 'g', 'o', 0xC0, 9}
			raw = binary.BigEndian.AppendUint16(raw, uint16(TypeA))
			raw = binary.BigEndian.AppendUint16(raw, uint16(ClassIN))
			raw = append(raw, []byte{3, 'd', 'e', 'v', 0}...)
			return raw
		}(),
		q: Question[MsgRawName]{
			Name:  newMsgRawName([]byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0}),
			Type:  TypeA,
			Class: ClassIN,
		},
		offset: 9,
	},

	{
		msg: func() []byte {
			raw := []byte{2, 'g', 'o', 0xC0, 32}
			raw = binary.BigEndian.AppendUint16(raw, uint16(TypeA))
			raw = binary.BigEndian.AppendUint16(raw, uint16(ClassIN))
			return raw
		}(),
		err: errInvalidDNSName,
	},

	{
		msg: func() []byte {
			raw := []byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0}
			raw = binary.BigEndian.AppendUint16(raw, uint16(TypeA))
			raw = binary.BigEndian.AppendUint16(raw, uint16(ClassIN))
			return raw[:len(raw)-1]
		}(),
		err: errInvalidDNSMessage,
	},
}

func TestQuestion(t *testing.T) {
	for i, v := range questionTests {
		prefix := fmt.Sprintf("%v: %v: ", i, v.msg)

		msg, err := NewMsg(v.msg)
		if err != nil {
			t.Errorf("%v unexpected NewMsg error: %v", prefix, err)
			continue
		}

		q, err := msg.Question()
		if err != v.err {
			t.Errorf("%v expected error: %v, but got: %v", prefix, v.err, err)
		}

		if err != nil {
			if off := msg.GetOffset(); off != 0 {
				t.Errorf("%v returned error, so offset should not change (expected 0), but got %v", prefix, off)
			}
			continue
		}

		if !(q.Name.Equal(&q.Name) && q.Type == v.q.Type && q.Class == v.q.Class) {
			expect := fmt.Sprintf("{Name: %v, Type: %v, Class: %v}", v.q.Name, v.q.Type, v.q.Class)
			got := fmt.Sprintf("{Name: %v, Type: %v, Class: %v}", q.Name, q.Type, q.Class)
			t.Errorf("%v expected: %v, but got: %v", prefix, expect, got)
		}

		if off := msg.GetOffset(); off != v.offset {
			t.Errorf("%v expected offset: %v, but got: %v", prefix, v.offset, off)
		}
	}
}

var resourceTests = []struct {
	length uint16
	msg    []byte
	res    any

	err    error
	offset uint16
}{
	{
		msg:    []byte{255, 1, 255, 1},
		length: 4,
		res:    ResourceA{A: [4]byte{255, 1, 255, 1}},
		offset: 4,
	},
	{
		msg:    []byte{255, 1, 255},
		length: 4,
		res:    ResourceA{},
		err:    errInvalidDNSMessage,
	},
	{
		msg:    []byte{255, 1, 255, 1},
		length: 3,
		res:    ResourceA{},
		err:    errInvalidDNSMessage,
	},
	{
		msg:    []byte{255, 1, 255, 1},
		length: 5,
		res:    ResourceA{},
		err:    errInvalidDNSMessage,
	},

	{
		msg:    bytes.Repeat([]byte{255, 1}, 8),
		length: 16,
		res:    ResourceAAAA{AAAA: *(*[16]byte)(bytes.Repeat([]byte{255, 1}, 8))},
		offset: 16,
	},
	{
		msg:    bytes.Repeat([]byte{255}, 15),
		length: 16,
		res:    ResourceAAAA{},
		err:    errInvalidDNSMessage,
	},
	{
		msg:    bytes.Repeat([]byte{255, 1}, 8),
		length: 15,
		res:    ResourceAAAA{},
		err:    errInvalidDNSMessage,
	},
	{
		msg:    bytes.Repeat([]byte{255, 1}, 8),
		length: 17,
		res:    ResourceAAAA{},
		err:    errInvalidDNSMessage,
	},

	{
		msg:    []byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0},
		length: 8,
		res:    ResourceCNAME{CNAME: newMsgRawName([]byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0})},
		offset: 8,
	},
	{
		msg:    []byte{2, 'g', 'o', 0xC0, 6, 32, 3, 'd', 'e', 'v', 0},
		length: 5,
		res:    ResourceCNAME{CNAME: newMsgRawName([]byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0})},
		offset: 5,
	},
	{
		msg:    []byte{2, 'g', 'o', 3},
		length: 4,
		res:    ResourceCNAME{},
		err:    errInvalidDNSName,
	},
	{
		msg:    []byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0},
		length: 7,
		res:    ResourceCNAME{},
		err:    errInvalidDNSMessage,
	},
	{
		msg:    []byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0},
		length: 9,
		res:    ResourceCNAME{},
		err:    errInvalidDNSMessage,
	},

	{
		msg: func() []byte {
			return append(binary.BigEndian.AppendUint16(nil, 10), []byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0}...)
		}(),
		length: 10,
		res:    ResourceMX{MX: newMsgRawName([]byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0}), Pref: 10},
		offset: 10,
	},
	{
		msg: func() []byte {
			return append(binary.BigEndian.AppendUint16(nil, 31111), []byte{2, 'g', 'o', 0xC0, 9, 32, 32, 3, 'd', 'e', 'v', 0}...)
		}(),
		length: 7,
		res:    ResourceMX{MX: newMsgRawName([]byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0}), Pref: 31111},
		offset: 7,
	},
	{
		msg: func() []byte {
			return append(binary.BigEndian.AppendUint16(nil, 10), []byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0}...)
		}(),
		length: 9,
		res:    ResourceMX{MX: newMsgRawName([]byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0}), Pref: 10},
		err:    errInvalidDNSMessage,
	},
	{
		msg: func() []byte {
			return append(binary.BigEndian.AppendUint16(nil, 10), []byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0}...)
		}(),
		length: 11,
		res:    ResourceMX{MX: newMsgRawName([]byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0}), Pref: 10},
		err:    errInvalidDNSMessage,
	},
	{
		msg: func() []byte {
			return []byte{1}
		}(),
		length: 4,
		res:    ResourceMX{},
		err:    errInvalidDNSMessage,
	},
	{
		msg: func() []byte {
			return binary.BigEndian.AppendUint16(nil, 10)
		}(),
		length: 3,
		res:    ResourceMX{},
		err:    errInvalidDNSName,
	},

	{
		msg:    []byte{3, 11, 11, 11},
		length: 4,
		res:    ResourceTXT{TXT: []byte{3, 11, 11, 11}},
		offset: 4,
	},
	{
		msg:    []byte{2, 44, 44, 3, 1, 1, 1},
		length: 7,
		res:    ResourceTXT{TXT: []byte{2, 44, 44, 3, 1, 1, 1}},
		offset: 7,
	},
	{
		msg:    []byte{3, 128, 128, 128, 1, 32, 4, 221, 191, 221, 205},
		length: 11,
		res:    ResourceTXT{TXT: []byte{3, 128, 128, 128, 1, 32, 4, 221, 191, 221, 205}},
		offset: 11,
	},
	{
		msg:    []byte{3, 11, 11, 11},
		length: 3,
		res:    ResourceTXT{},
		err:    errInvalidDNSMessage,
	},
	{
		msg:    []byte{3, 11, 11, 11},
		length: 5,
		res:    ResourceTXT{},
		err:    errInvalidDNSMessage,
	},
	{
		msg:    []byte{8, 11, 11, 11, 11, 11},
		length: 6,
		res:    ResourceTXT{},
		err:    errInvalidDNSMessage,
	},
}

func newMsgRawName(buf []byte) MsgRawName {
	msg, err := NewMsg(buf)
	if err != nil {
		panic(err)
	}

	name := MsgRawName{
		m:         &msg,
		nameStart: 0,
	}

	err = name.unpack()
	if err != nil {
		panic(err)
	}

	return name
}

func newMsgRawNameOffset(buf []byte, off uint16) MsgRawName {
	msg, err := NewMsg(buf)
	if err != nil {
		panic(err)
	}

	name := MsgRawName{
		m:         &msg,
		nameStart: off,
	}

	err = name.unpack()
	if err != nil {
		panic(err)
	}

	return name
}

func TestResource(t *testing.T) {
	for i, v := range resourceTests {
		prefix := fmt.Sprintf("%v: %T: %v", i, v.res, v.msg)

		msg, err := NewMsg(v.msg)
		if err != nil {
			t.Errorf("%v unexpected NewMsg error: %v", prefix, err)
			continue
		}

		if v.length == 0 {
			v.length = uint16(len(v.msg))
		}

		var out any
		switch v.res.(type) {
		case ResourceA:
			out, err = msg.ResourceA(v.length)
		case ResourceAAAA:
			out, err = msg.ResourceAAAA(v.length)
		case ResourceCNAME:
			out, err = msg.ResourceCNAME(v.length)
		case ResourceMX:
			out, err = msg.ResourceMX(v.length)
		case ResourceTXT:
			out, err = msg.ResourceTXT(v.length)
		default:
			t.Fatal("internal test error")
		}

		if err != v.err {
			t.Errorf("%v expected error: %v but: %v", prefix, v.err, err)
		}

		if err != nil {
			if off := msg.GetOffset(); off != 0 {
				t.Errorf("%v returned error, so offset should not change (expected 0), but got %v", prefix, off)
			}
			continue
		}

		var eq bool
		switch expect := v.res.(type) {
		case ResourceA, ResourceAAAA:
			eq = v.res == out
		case ResourceCNAME:
			res := out.(ResourceCNAME)
			eq = expect.CNAME.Equal(&res.CNAME)
		case ResourceMX:
			res := out.(ResourceMX)
			eq = expect.MX.Equal(&res.MX) && expect.Pref == res.Pref
		case ResourceTXT:
			res := out.(ResourceTXT)
			eq = bytes.Equal(res.TXT, expect.TXT)
		default:
			t.Fatal("internal test error")
		}

		if !eq {
			t.Errorf("%v expected: %v, but got: %v", prefix, v.res, out)
		}

		if off := msg.GetOffset(); off != v.offset {
			t.Errorf("%v expected offset: %v, but got: %v", prefix, v.offset, off)
		}
	}
}

var msgRawName MsgRawName

func BenchmarkNameUnpack(b *testing.B) {
	benchMsg := []byte{3, 'w', 'w', 'w', 2, 'g', 'o', 3, 'd', 'e', 'v', 0, 64, 64, 64}
	msg, _ := NewMsg(benchMsg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m := MsgRawName{
			m:         &msg,
			nameStart: 0,
		}

		_ = m.unpack()

		msgRawName = m
	}
}

var nameUnpackTests = []struct {
	name string

	msg       []byte
	nameStart uint16

	err         error
	noFollowLen uint8
	rawLen      uint8
}{
	{
		msg:         []byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0, 64, 64, 64},
		nameStart:   0,
		err:         nil,
		noFollowLen: 8,
		rawLen:      8,
	},

	{
		msg:         []byte{32, 32, 2, 'g', 'o', 3, 'd', 'e', 'v', 0, 64, 64, 64},
		nameStart:   2,
		err:         nil,
		noFollowLen: 8,
		rawLen:      8,
	},

	{
		msg:         []byte{32, 32, 3, 'd', 'e', 'v', 0, 16, 16, 16, 3, 'w', 'w', 'w', 2, 'g', 'o', 0xC0, 2, 64, 64, 64},
		nameStart:   10,
		err:         nil,
		noFollowLen: 9,
		rawLen:      12,
	},

	{
		name: "255B domain",
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
			return buf
		}(),
		nameStart:   0,
		err:         nil,
		noFollowLen: 255,
		rawLen:      255,
	},

	{
		name: "255B domain with one compression pointer",
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
			return buf
		}(),
		nameStart:   0,
		err:         nil,
		noFollowLen: 64,
		rawLen:      255,
	},

	{
		name: "256B domain",
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
			return buf
		}(),
		nameStart: 0,
		err:       errInvalidDNSName,
	},

	{
		name: "256B domain with one compression pointer",
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
			return buf
		}(),
		nameStart: 0,
		err:       errInvalidDNSName,
	},

	{
		msg:       []byte{3, 'w', 'w', 'w', 0xC0, 0, 32},
		nameStart: 0,
		err:       errPtrLoop,
	},

	{
		msg:       []byte{32, 32, 0xC0, 2, 32},
		nameStart: 2,
		err:       errPtrLoop,
	},

	{
		msg:       []byte{0b01000000}, // reserved label bit
		nameStart: 0,
		err:       errInvalidDNSName,
	},

	{
		msg:       []byte{0b10000000}, // reserved label bit
		nameStart: 0,
		err:       errInvalidDNSName,
	},
}

func TestNameUnpack(t *testing.T) {
	for i, v := range nameUnpackTests {
		prefix := fmt.Sprintf("%v: %v: ", i, v.msg)
		if len(v.name) != 0 {
			prefix = fmt.Sprintf("%v: %v: %v: ", i, v.name, v.msg)
		}

		msg, err := NewMsg(v.msg)
		if err != nil {
			t.Errorf("%v unexpected NewMsg() error: %v", prefix, err)
			continue
		}

		m := MsgRawName{
			m:         &msg,
			nameStart: v.nameStart,
		}

		err = m.unpack()
		if err != v.err {
			t.Errorf("%v expected error: %v, got: %v", prefix, v.err, err)
			continue
		}

		if err != nil {
			if n := m.NoFollowLen(); n != 0 {
				t.Errorf("%v expected NoFollowLen to be equal to 0, but %v", prefix, n)
				continue
			}
			continue
		}

		if n := m.NoFollowLen(); n != v.noFollowLen {
			t.Errorf("%v expected NoFollowLen to be equal to %v, but %v", prefix, v.noFollowLen, n)
		}

		if r := m.RawLen(); r != v.rawLen {
			t.Errorf("%v expected RawLen to be equal to %v, but %v", prefix, v.rawLen, r)
		}
	}
}

func prepNameSameMsg(buf []byte, n1Start, n2Start uint16) [2]MsgRawName {
	msg, err := NewMsg(buf)
	if err != nil {
		panic(err)
	}

	m1 := MsgRawName{m: &msg, nameStart: n1Start}
	err = m1.unpack()
	if err != nil {
		panic(err)
	}

	m2 := MsgRawName{m: &msg, nameStart: n2Start}
	err = m2.unpack()
	if err != nil {
		panic(err)
	}

	var n [2]MsgRawName
	n[0] = m1
	n[1] = m2
	return n
}

func prepNameDifferentMsg(buf1, buf2 []byte, n1Start, n2Start uint16) [2]MsgRawName {
	msg1, err := NewMsg(buf1)
	if err != nil {
		panic(err)
	}

	msg2, err := NewMsg(buf2)
	if err != nil {
		panic(err)
	}

	m1 := MsgRawName{m: &msg1, nameStart: n1Start}
	err = m1.unpack()
	if err != nil {
		panic(err)
	}

	m2 := MsgRawName{m: &msg2, nameStart: n2Start}
	err = m2.unpack()
	if err != nil {
		panic(err)
	}

	var n [2]MsgRawName
	n[0] = m1
	n[1] = m2
	return n
}

var nameEqualTests = []struct {
	name string

	names [2]MsgRawName
	equal bool
}{
	{
		name: "(same msg) equal nameStart",
		names: prepNameSameMsg([]byte{
			32, 32, 2, 'g', 'o', 3, 'd', 'e', 'v', 0,
		}, 2, 2),
		equal: true,
	},

	{
		name: "(same msg) compression pointer (first label) of second name points to beggining of the first name",
		names: prepNameSameMsg([]byte{
			32, 32, 2, 'g', 'o', 3, 'd', 'e', 'v', 0,
			0xC0, 2,
		}, 2, 10),
		equal: true,
	},

	{
		name: "(same msg) (no pointers) two separate (same) names",
		names: prepNameSameMsg([]byte{
			32, 32, 2, 'g', 'o', 3, 'd', 'e', 'v', 0,
			2, 'g', 'o', 3, 'd', 'e', 'v', 0,
		}, 2, 10),
		equal: true,
	},

	{
		name: "(same msg) (no pointers) two separate (same) names with different letter case",
		names: prepNameSameMsg([]byte{
			32, 32, 2, 'G', 'o', 3, 'd', 'E', 'V', 0,
			2, 'g', 'O', 3, 'D', 'e', 'v', 0,
		}, 2, 10),
		equal: true,
	},

	{
		name: "(same msg) (no pointers) two different names",
		names: prepNameSameMsg([]byte{
			32, 32, 2, 'g', 'o', 3, 'd', 'e', 'b', 0,
			3, 'w', 'w', 'w', 2, 'g', 'o', 3, 'd', 'e', 'v', 0,
		}, 2, 10),
		equal: false,
	},

	{
		name: "(same msg) (no pointers) two different names (2)",
		names: prepNameSameMsg([]byte{
			32, 32, 2, 'g', 'o', 3, 'd', 'e', 'b', 0,
			2, 'g', 'o', 2, 'g', 'o', 3, 'd', 'e', 'v', 0,
		}, 2, 10),
		equal: false,
	},

	{
		name: "(same msg) (with pointers) two different names",
		names: prepNameSameMsg([]byte{
			32, 32, 2, 'G', 'o', 3, 'd', 'R', 'V', 0,
			3, 'w', 'w', 'w', 0xC0, 2,
		}, 2, 10),
		equal: false,
	},

	{
		name: "(same msg) (no pointers) different names, different label length",
		names: prepNameSameMsg([]byte{
			32, 32, 3, 'w', 'w', 'w', 2, 'g', 'o', 3, 'd', 'e', 'v', 0,
			4, 'i', 'm', 'a', 'p', 2, 'g', 'o', 3, 'd', 'e', 'v', 0,
		}, 2, 14),
		equal: false,
	},

	{
		name: "(same msg) (with pointers) different names, different label length",
		names: prepNameSameMsg([]byte{
			2, 'g', 'o', 3, 'd', 'e', 'v', 0,
			3, 'w', 'w', 'w', 0xC0, 0,
			4, 'i', 'm', 'a', 'p', 0xC0, 0,
		}, 8, 14),
		equal: false,
	},

	{
		name: "(different msgs) (no pointers) same names",
		names: prepNameDifferentMsg([]byte{
			2, 'g', 'o', 3, 'd', 'e', 'v', 0,
		}, []byte{
			2, 'g', 'o', 3, 'd', 'e', 'v', 0,
		}, 0, 0),
		equal: true,
	},

	{
		name: "(different msgs) (no pointers) same names, different letter case",
		names: prepNameDifferentMsg([]byte{
			2, 'G', 'o', 3, 'd', 'E', 'V', 0,
		}, []byte{
			2, 'G', 'O', 3, 'D', 'e', 'v', 0,
		}, 0, 0),
		equal: true,
	},

	{
		name: "(different msgs) (no pointers) different names",
		names: prepNameDifferentMsg([]byte{
			2, 'g', 'o', 3, 'd', 'e', 'v', 0,
		}, []byte{
			2, 'g', 'o', 2, 'g', 'o', 3, 'd', 'e', 'v', 0,
		}, 0, 0),
		equal: false,
	},

	{
		name: "(different msgs) (with pointers) same names",
		names: prepNameDifferentMsg([]byte{
			2, 'g', 'o', 3, 'd', 'e', 'v', 0,
		}, []byte{
			3, 'd', 'e', 'v', 0, 2, 'g', 'o', 0xC0, 0,
		}, 0, 5),
		equal: true,
	},

	{
		name: "(different msgs) (with pointers) different names",
		names: prepNameDifferentMsg([]byte{
			2, 'g', 'o', 3, 'd', 'e', 'v', 0,
		}, []byte{
			3, 'd', 'e', 'v', 0, 2, 'g', 'o', 2, 'g', 'o', 0xC0, 0,
		}, 0, 5),
		equal: false,
	},

	{
		name: "(same msg) (no pointers) two separate different names (diffrent label ending character)",
		names: prepNameSameMsg([]byte{
			2, 'g', 'o', 3, 'd', 'e', 'v', 0,
			2, 'g', 'l', 3, 'd', 'e', 'v', 0,
		}, 0, 8),
		equal: false,
	},
}

func TestNameEqual(t *testing.T) {
	for i, v := range nameEqualTests {
		for ti, tv := range []string{"normal n[0].Equal(n[1])", "reverse n[1].Equal(n[0])"} {
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

var nameEqualRawTests = []struct {
	name  MsgRawName
	name2 []byte

	eq bool
}{
	{
		name:  newMsgRawName([]byte{0}),
		name2: []byte{0},
		eq:    true,
	},
	{
		name:  newMsgRawName([]byte{3, 'c', 'o', 'm', 0}),
		name2: []byte{3, 'c', 'o', 'm', 0},
		eq:    true,
	},
	{
		name:  newMsgRawName([]byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0}),
		name2: []byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0},
		eq:    true,
	},
	{
		name:  newMsgRawName([]byte{3, 'w', 'w', 'w', 2, 'g', 'o', 3, 'd', 'e', 'v', 0}),
		name2: []byte{3, 'w', 'w', 'w', 2, 'g', 'o', 3, 'd', 'e', 'v', 0},
		eq:    true,
	},
	{
		name:  newMsgRawName([]byte{3, 'w', 'w', 'a', 2, 'g', 'o', 3, 'd', 'e', 'v', 0}),
		name2: []byte{3, 'w', 'w', 'w', 2, 'g', 'o', 3, 'd', 'e', 'v', 0},
		eq:    false,
	},
	{
		name:  newMsgRawName([]byte{4, 'w', 'w', 'w', 'w', 2, 'g', 'o', 3, 'd', 'e', 'v', 0}),
		name2: []byte{3, 'w', 'w', 'w', 2, 'g', 'o', 3, 'd', 'e', 'v', 0},
		eq:    false,
	},
	{
		name:  newMsgRawNameOffset([]byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0, 32, 32, 3, 'w', 'w', 'w', 0xC0, 0}, 10),
		name2: []byte{3, 'w', 'w', 'w', 2, 'g', 'o', 3, 'd', 'e', 'v', 0},
		eq:    true,
	},
	{
		name:  newMsgRawNameOffset([]byte{2, 'g', 'O', 3, 'd', 'E', 'v', 0, 32, 32, 3, 'W', 'w', 'W', 0xC0, 0}, 10),
		name2: []byte{3, 'W', 'W', 'w', 2, 'g', 'O', 3, 'D', 'E', 'V', 0},
		eq:    true,
	},
	{
		name:  newMsgRawName([]byte{3, 'c', 'o', 'm', 0}),
		name2: []byte{3, 'c', 'o'},
		eq:    false,
	},

	{
		name:  newMsgRawName([]byte{3, 'c', 'o', 'm', 0}),
		name2: []byte{},
		eq:    false,
	},
}

func TestNameEqualRaw(t *testing.T) {
	for i, v := range nameEqualRawTests {
		prefix := fmt.Sprintf("%v: %v:", i, v.name2)

		if eq := v.name.EqualRaw(v.name2); eq != v.eq {
			t.Errorf("%v expected: %v, but: %v", prefix, v.eq, eq)
		}
	}
}

func FuzzNameEqualRaw(f *testing.F) {
	for _, v := range nameEqualRawTests {
		f.Add(v.name.m.msg, v.name.nameStart, v.name2)
	}

	f.Fuzz(func(_ *testing.T, a []byte, nameStart uint16, name2 []byte) {
		msg, err := NewMsg(a)
		if err != nil {
			return
		}

		name := MsgRawName{
			m:         &msg,
			nameStart: nameStart,
		}

		err = name.unpack()
		if err != nil {
			return
		}

		name.EqualRaw(name2)
	})
}

func BenchmarkEqualSameMsgNoCompression(b *testing.B) {
	names := prepNameSameMsg([]byte{
		32, 32, 3, 'w', 'w', 'w', 2, 'g', 'o', 3, 'd', 'e', 'v', 0,
		3, 'w', 'w', 'w', 2, 'g', 'o', 3, 'd', 'e', 'v', 0,
	}, 2, 14)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		names[0].Equal(&names[1])
	}
}

func BenchmarkEqualSameMsgCompressionPointer(b *testing.B) {
	names := prepNameSameMsg([]byte{
		32, 32, 3, 'w', 'w', 'w', 2, 'g', 'o', 3, 'd', 'e', 'v', 0,
		3, 'w', 'w', 'w', 0xC0, 6,
	}, 2, 14)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		names[0].Equal(&names[1])
	}
}

func BenchmarkEqualSameMsgDirectCompressionPointer(b *testing.B) {
	names := prepNameSameMsg([]byte{
		32, 32, 3, 'w', 'w', 'w', 2, 'g', 'o', 3, 'd', 'e', 'v', 0,
		0xC0, 2,
	}, 2, 14)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		names[0].Equal(&names[1])
	}
}

var nameEqualStringTests = []struct {
	msgRawName  MsgRawName
	name        string
	noAppendDot bool

	eq bool
}{
	{
		msgRawName:  newMsgRawName([]byte{0}),
		name:        ".",
		noAppendDot: true,
		eq:          true,
	},

	{
		msgRawName:  newMsgRawName([]byte{0xC0, 3, 32, 0}),
		name:        ".",
		noAppendDot: true,
		eq:          true,
	},

	{
		msgRawName: newMsgRawName([]byte{3, 'c', 'o', 'm', 0}),
		name:       "com",
		eq:         true,
	},

	{
		msgRawName: newMsgRawName([]byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0}),
		name:       "go.dev",
		eq:         true,
	},

	{
		msgRawName: newMsgRawName([]byte{2, 'G', 'o', 3, 'd', 'E', 'v', 0}),
		name:       "gO.DEv",
		eq:         true,
	},

	{
		msgRawName: newMsgRawName([]byte{3, 'w', 'w', 'w', 2, 'g', 'o', 3, 'd', 'e', 'v', 0}),
		name:       "www.go.dev",
		eq:         true,
	},

	{
		msgRawName: newMsgRawName([]byte{3, 'w', 'w', 'w', 2, 'g', 'o', 3, 'd', 'e', 'v', 0}),
		name:       "imap.go.dev",
		eq:         false,
	},

	{
		msgRawName: newMsgRawName([]byte{3, 'w', 'w', 'w', 2, 'g', 'o', 3, 'd', 'e', 'v', 0}),
		name:       "sth.go.dev",
		eq:         false,
	},

	{
		msgRawName: newMsgRawNameOffset([]byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0, 32, 32, 3, 'w', 'w', 'w', 0xC0, 0}, 10),
		name:       "www.go.dev",
		eq:         true,
	},

	{
		msgRawName: newMsgRawNameOffset([]byte{2, 'G', 'o', 3, 'd', 'E', 'v', 0, 32, 32, 3, 'w', 'W', 'w', 0xC0, 0}, 10),
		name:       "wwW.go.dEv",
		eq:         true,
	},

	{
		msgRawName: newMsgRawNameOffset([]byte{2, 'G', 'o', 3, 'd', 'E', 'v', 0, 32, 32, 3, 'w', 'W', 'w', 0xC0, 0}, 10),
		name:       "wwR.go.dEv",
		eq:         false,
	},

	{
		msgRawName: newMsgRawNameOffset([]byte{2, 'G', 'o', 3, 'd', 'E', 'v', 0, 32, 32, 3, 'w', 'W', 'w', 0xC0, 0}, 10),
		name:       "wwww.go.dEv",
		eq:         false,
	},

	{
		msgRawName: newMsgRawNameOffset([]byte{2, 'G', 'o', 3, 'd', 'E', 'v', 0, 32, 32, 3, 'w', 'W', 'w', 0xC0, 0}, 10),
		name:       "www.golang.org",
		eq:         false,
	},

	{
		msgRawName: newMsgRawName([]byte{1, '\\', 0}),
		name:       "\\",
		eq:         false,
	},
	{
		msgRawName: newMsgRawName([]byte{1, '\\', 0}),
		name:       "\\\\",
		eq:         true,
	},

	{
		msgRawName: newMsgRawName([]byte{3, 'w', '.', 'w', 0}),
		name:       "w.w",
		eq:         false,
	},
	{
		msgRawName: newMsgRawName([]byte{3, '.', '.', '.', 0}),
		name:       "...",
		eq:         false,
	},
	{
		msgRawName: newMsgRawName([]byte{3, '.', '.', '.', 0}),
		name:       "\\.\\.\\.",
		eq:         true,
	},

	{
		msgRawName: newMsgRawName([]byte{3, 'w', '.', 'w', 2, 'g', 'o', 3, 'd', 'e', 'v', 0}),
		name:       "w\\.w.go.dev",
		eq:         true,
	},
	{
		msgRawName: newMsgRawName([]byte{3, 'w', '\\', 'w', 2, 'g', 'o', 3, 'd', 'e', 'v', 0}),
		name:       "w\\\\w.go.dev",
		eq:         true,
	},
	{
		msgRawName: newMsgRawName([]byte{3, 'w', 'w', 'w', 2, 'g', 'o', 3, 'd', 'e', 'v', 0}),
		name:       "w\\ww.g\\o.\\dev",
		eq:         true,
	},
	{
		msgRawName: newMsgRawName([]byte{3, 'w', 'w', 'w', 2, 'g', 'o', 3, 'd', 'e', 'v', 0}),
		name:       "w\\087w.\\103o.d\\101v", // wWw.go.dev
		eq:         true,
	},

	{
		msgRawName: newMsgRawName([]byte{1, 0, 0}),
		name:       "\\256",
		eq:         false,
	},

	{
		msgRawName:  newMsgRawName([]byte{0}),
		name:        "\\.",
		noAppendDot: true,
		eq:          false,
	},

	{
		msgRawName: newMsgRawName([]byte{1, 7, 0}),
		name:       "\\07",
		eq:         false,
	},
	{
		msgRawName: newMsgRawName([]byte{1, 0, 0}),
		name:       "\\0",
		eq:         false,
	},
}

func TestNameEqualString(t *testing.T) {
	for i, v := range nameEqualStringTests {
		for _, vappend := range []string{"", "."} {
			if v.noAppendDot && vappend == "." {
				continue
			}

			name := v.name + vappend
			prefix := fmt.Sprintf("%v: %v: ", i, name)

			if eq := v.msgRawName.EqualString(name); eq != v.eq {
				t.Errorf("%v expected: %v, but: %v", prefix, v.eq, eq)
			}
		}
	}
}

func TestNameEqualBytes(t *testing.T) {
	for i, v := range nameEqualStringTests {
		for _, vappend := range []string{"", "."} {
			if v.noAppendDot && vappend == "." {
				continue
			}

			name := []byte(v.name + vappend)
			prefix := fmt.Sprintf("%v: %v: ", i, name)

			if eq := v.msgRawName.EqualBytes(name); eq != v.eq {
				t.Errorf("%v expected: %v, but: %v", prefix, v.eq, eq)
			}
		}
	}
}

func BenchmarkEqualString(b *testing.B) {
	name := newMsgRawNameOffset([]byte{2, 'G', 'o', 3, 'd', 'E', 'v', 0, 32, 32, 3, 'w', 'W', 'w', 0xC0, 0}, 10)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		name.EqualString("www.go.dev.")
	}
}

func BenchmarkEqualBytes(b *testing.B) {
	name := newMsgRawNameOffset([]byte{2, 'G', 'o', 3, 'd', 'E', 'v', 0, 32, 32, 3, 'w', 'W', 'w', 0xC0, 0}, 10)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		name.EqualBytes([]byte("www.go.dev."))
	}
}

func FuzzEqualString(f *testing.F) {
	for _, v := range nameEqualStringTests {
		f.Add(v.msgRawName.m.msg, v.msgRawName.nameStart, v.name)

		if !v.noAppendDot {
			f.Add(v.msgRawName.m.msg, v.msgRawName.nameStart, v.name+".")
		}
	}

	f.Fuzz(func(_ *testing.T, a []byte, nameStart uint16, name2 string) {
		msg, err := NewMsg(a)
		if err != nil {
			return
		}

		name := MsgRawName{
			m:         &msg,
			nameStart: nameStart,
		}

		err = name.unpack()
		if err != nil {
			return
		}

		name.EqualString(name2)
	})
}

func FuzzEqualBytes(f *testing.F) {
	for _, v := range nameEqualStringTests {
		f.Add(v.msgRawName.m.msg, v.msgRawName.nameStart, []byte(v.name))

		if !v.noAppendDot {
			f.Add(v.msgRawName.m.msg, v.msgRawName.nameStart, []byte(v.name+"."))
		}
	}

	f.Fuzz(func(_ *testing.T, a []byte, nameStart uint16, name2 []byte) {
		msg, err := NewMsg(a)
		if err != nil {
			return
		}

		name := MsgRawName{
			m:         &msg,
			nameStart: nameStart,
		}

		err = name.unpack()
		if err != nil {
			return
		}

		name.EqualBytes(name2)
	})
}

var stringTests = []struct {
	name MsgRawName
	out  string
}{
	{
		name: newMsgRawName([]byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0}),
		out:  "go.dev.",
	},

	{
		name: newMsgRawName([]byte{3, 'w', 'w', 'w', 2, 'g', 'o', 3, 'd', 'e', 'v', 0}),
		out:  "www.go.dev.",
	},

	{
		name: newMsgRawNameOffset([]byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0, 32, 32, 3, 'w', 'w', 'w', 0xC0, 0}, 10),
		out:  "www.go.dev.",
	},

	{
		name: newMsgRawName([]byte{3, 'w', '.', 'w', 2, 'g', 'o', 3, 'd', 'e', 'v', 0}),
		out:  "w\\.w.go.dev.",
	},
	{
		name: newMsgRawName([]byte{3, 'w', '\\', 'w', 2, 'g', 'o', 3, 'd', 'e', 'v', 0}),
		out:  "w\\\\w.go.dev.",
	},

	{
		name: newMsgRawName([]byte{4, 3, 'w', 32, 'w', 4, 'w', 127, 'w', 255, 2, 'g', 'o', 3, 'd', 'e', 'v', 0}),
		out:  "\\003w\\032w.w\\127w\\255.go.dev.",
	},
}

func TestString(t *testing.T) {
	for i, v := range stringTests {
		prefix := fmt.Sprintf("%v: %v: ", i, v.out)

		if str := v.name.String(); str != v.out {
			t.Errorf("%v expected %v, but got %v", prefix, v.out, str)
		}
	}
}

func TestBytes(t *testing.T) {
	for i, v := range stringTests {
		prefix := fmt.Sprintf("%v: %v: ", i, v.out)

		if b := v.name.Bytes(); !bytes.Equal(b, []byte(v.out)) {
			t.Errorf("%v (Bytes) expected %v, but got %v", prefix, []byte(v.out), b)
		}

		if b := v.name.AppendBytes(nil); !bytes.Equal(b, []byte(v.out)) {
			t.Errorf("%v (AppendBytes) expected %v, but got %v", prefix, []byte(v.out), b)
		}
	}
}

func BenchmarkString(b *testing.B) {
	name := newMsgRawNameOffset([]byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0, 32, 32, 3, 'w', 'w', 'w', 0xC0, 0}, 10)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		name.String()
	}
}

var rawNameTests = []struct {
	name    MsgRawName
	rawName []byte
}{
	{
		name:    newMsgRawName([]byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0}),
		rawName: []byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0},
	},

	{
		name:    newMsgRawName([]byte{3, 'w', 'w', 'w', 2, 'g', 'o', 3, 'd', 'e', 'v', 0}),
		rawName: []byte{3, 'w', 'w', 'w', 2, 'g', 'o', 3, 'd', 'e', 'v', 0},
	},
	{
		name:    newMsgRawNameOffset([]byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0, 32, 32, 3, 'w', 'w', 'w', 0xC0, 0}, 10),
		rawName: []byte{3, 'w', 'w', 'w', 2, 'g', 'o', 3, 'd', 'e', 'v', 0},
	},
}

func TestRawName(t *testing.T) {
	for i, v := range rawNameTests {
		prefix := fmt.Sprintf("%v: %v: ", i, v.rawName)

		raw := v.name.RawName()
		rawAppend := v.name.AppendRawName(nil)

		if !bytes.Equal(v.rawName, raw) {
			t.Errorf("%v (RawName) expected %v, but got %v", prefix, v.rawName, raw)
		}

		if !bytes.Equal(v.rawName, rawAppend) {
			t.Errorf("%v (AppendRawName) expected %v, but got %v", prefix, v.rawName, rawAppend)
		}
	}
}
