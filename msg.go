package parser

import (
	"errors"
	"math"
)

var (
	errInvalidDNSMessage = errors.New("err invalid dns message")
	errInvalidDNSName    = errors.New("invalid dns name")
	errPtrLoop           = errors.New("dns compression pointer loop")
	errDNSMsgTooLong     = errors.New("too long dns message, max supported length: 65535 Bytes")
)

//TODO: use binary.BigEndian in entire package (because of lower cost (golang/go#42958)) (but probably after golang/go#54097 gets fixed)

func unpackUint16(b []byte) uint16 {
	return uint16(b[0])<<8 | uint16(b[1])
}

func unpackUint32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func NewMsg(msg []byte) (Msg, error) {
	if len(msg) > math.MaxUint16 {
		return Msg{}, errDNSMsgTooLong
	}

	return Msg{
		msg: msg,
	}, nil
}

type Msg struct {
	msg       []byte
	curOffset uint16
}

func (m *Msg) Len() int {
	return len(m.msg)
}

func (m *Msg) SetOffset(off uint16) {
	m.curOffset = off
}

func (m *Msg) GetOffset() uint16 {
	return m.curOffset
}

func (m *Msg) Header() (Header, error) {
	var hdr Header
	offset, err := hdr.unpack(m.msg[m.curOffset:])
	m.curOffset += offset
	return hdr, err
}

func (m *Msg) Question() (Question[MsgRawName], error) {
	q := Question[MsgRawName]{
		Name: MsgRawName{
			m:         m,
			nameStart: m.curOffset,
		},
	}

	err := q.Name.unpack()
	if err != nil {
		return Question[MsgRawName]{}, err
	}

	tmpOffset := m.curOffset + uint16(q.Name.NoFollowLen())

	if len(m.msg[tmpOffset:]) < 4 {
		return Question[MsgRawName]{}, errInvalidDNSMessage
	}

	q.Type = Type(unpackUint16(m.msg[tmpOffset : tmpOffset+2]))
	q.Class = Class(unpackUint16(m.msg[tmpOffset+2 : tmpOffset+4]))
	m.curOffset = tmpOffset + 4

	return q, nil
}

func (m *Msg) ResourceHeader() (ResourceHeader[MsgRawName], error) {
	q := ResourceHeader[MsgRawName]{
		Name: MsgRawName{
			m:         m,
			nameStart: m.curOffset,
		},
	}

	err := q.Name.unpack()
	if err != nil {
		return ResourceHeader[MsgRawName]{}, err
	}

	tmpOffset := m.curOffset + uint16(q.Name.NoFollowLen())

	if len(m.msg[tmpOffset:]) < 10 {
		return ResourceHeader[MsgRawName]{}, errInvalidDNSMessage
	}

	q.Type = Type(unpackUint16(m.msg[tmpOffset : tmpOffset+2]))
	q.Class = Class(unpackUint16(m.msg[tmpOffset+2 : tmpOffset+4]))
	q.TTL = unpackUint32(m.msg[tmpOffset+4 : tmpOffset+8])
	q.Length = unpackUint16(m.msg[tmpOffset+8 : tmpOffset+10])
	m.curOffset = tmpOffset + 10

	return q, nil
}

func (m *Msg) Skip(length uint16) error {
	if len(m.msg[m.curOffset:]) < int(length) {
		return errInvalidDNSMessage
	}

	m.curOffset += length
	return nil
}

func (m *Msg) RawResource(length uint16) ([]byte, error) {
	if len(m.msg[m.curOffset:]) < int(length) {
		return nil, errInvalidDNSMessage
	}

	msg := m.msg[m.curOffset : m.curOffset+length]
	m.curOffset += length

	return msg, nil
}

func (m *Msg) ResourceA(length uint16) (ResourceA, error) {
	if len(m.msg[m.curOffset:]) < 4 || length != 4 {
		return ResourceA{}, errInvalidDNSMessage
	}

	m.curOffset += 4
	return ResourceA{
		A: *(*[4]byte)(m.msg[m.curOffset-4 : m.curOffset]),
	}, nil
}

func (m *Msg) ResourceAAAA(length uint16) (ResourceAAAA, error) {
	if len(m.msg[m.curOffset:]) < 16 || length != 16 {
		return ResourceAAAA{}, errInvalidDNSMessage
	}

	m.curOffset += 16
	return ResourceAAAA{
		AAAA: *(*[16]byte)(m.msg[m.curOffset-16 : m.curOffset]),
	}, nil
}

func (m *Msg) ResourceCNAME(RDLength uint16) (ResourceCNAME, error) {
	r := ResourceCNAME{
		CNAME: MsgRawName{
			m:         m,
			nameStart: m.curOffset,
		},
	}

	err := r.CNAME.unpack()
	if err != nil {
		return ResourceCNAME{}, err
	}

	if uint16(r.CNAME.NoFollowLen()) != RDLength {
		return ResourceCNAME{}, errInvalidDNSMessage
	}

	m.curOffset += uint16(r.CNAME.NoFollowLen())
	return r, nil
}

func (m *Msg) ResourceMX(RDLength uint16) (ResourceMX, error) {
	r := ResourceMX{
		MX: MsgRawName{
			m:         m,
			nameStart: m.curOffset + 2,
		},
	}

	if len(m.msg[m.curOffset:]) < 2 {
		return ResourceMX{}, errInvalidDNSMessage
	}

	r.Pref = unpackUint16(m.msg[m.curOffset : m.curOffset+2])

	err := r.MX.unpack()
	if err != nil {
		return ResourceMX{}, err
	}

	if uint16(r.MX.NoFollowLen()) != RDLength-2 {
		return ResourceMX{}, errInvalidDNSMessage
	}

	m.curOffset += uint16(r.MX.NoFollowLen()) + 2
	return r, nil
}

func (m *Msg) ResourceTXT(RDLength uint16) (ResourceTXT, error) {
	if len(m.msg[m.curOffset:]) < int(RDLength) {
		return ResourceTXT{}, errInvalidDNSMessage
	}

	r := ResourceTXT{
		TXT: m.msg[m.curOffset : m.curOffset+RDLength],
	}

	for i := 0; i < len(r.TXT); {
		i += int(r.TXT[i]) + 1
		if i == len(r.TXT) {
			m.curOffset += RDLength
			return r, nil
		}
	}

	return ResourceTXT{}, errInvalidDNSMessage
}

type MsgRawName struct {
	m         *Msg
	nameStart uint16

	lenNoPtr uint8
}

const ptrLoopCount = 16

// Equal reports whether m and m2 represents the same name.
// It does not require identical internal representation of the name.
func (m *MsgRawName) Equal(m2 *MsgRawName) bool {
	im1 := m.nameStart
	im2 := m2.nameStart

	for {
		// Resolve all (in a row) compression pointers of m
		for m.m.msg[im1]&0xC0 == 0xC0 {
			im1 = uint16(m.m.msg[im1]^0xC0)<<8 | uint16(m.m.msg[im1+1])
		}

		// Resolve all (in a row) compression pointers of m2
		for m2.m.msg[im2]&0xC0 == 0xC0 {
			im2 = uint16(m2.m.msg[im2]^0xC0)<<8 | uint16(m2.m.msg[im2+1])
		}

		// if we point to the same location, then it is equal.
		if m.m == m2.m && im1 == im2 {
			return true
		}

		// different label lengths
		if m.m.msg[im1] != m2.m.msg[im2] {
			return false
		}

		if m.m.msg[im1] == 0 {
			return true
		}

		if !equal(m.m.msg[im1+1:im1+1+uint16(m.m.msg[im1])], m2.m.msg[im2+1:im2+1+uint16(m2.m.msg[im2])]) {
			return false
		}

		im1 += uint16(m.m.msg[im1]) + 1
		im2 += uint16(m2.m.msg[im2]) + 1
	}
}

// len(a) must be equal to len(b)
func equal(a, b []byte) bool {
	for i := 0; i < len(a); i++ {
		if !equalASCIICaseInsensitive(a[i], b[i]) {
			return false
		}
	}
	return true
}

func equalASCIICaseInsensitive(a, b byte) bool {
	const caseDiff = 'a' - 'A'

	if a >= 'a' && a <= 'z' {
		a -= caseDiff
	}

	if b >= 'a' && b <= 'z' {
		b -= caseDiff
	}

	return a == b
}

func (m *MsgRawName) rawName() []byte {
	raw := make([]byte, 0, m.lenNoPtr)

	i := m.nameStart
	for {
		if m.m.msg[i]&0xC0 == 0xC0 {
			i = uint16(m.m.msg[i]^0xC0)<<8 | uint16(m.m.msg[i+1])
			continue
		}

		if m.m.msg[i] == 0 {
			raw = append(raw, 0)
			return raw
		}

		raw = append(raw, m.m.msg[i:i+uint16(m.m.msg[i])+1]...)
		i += uint16(m.m.msg[i]) + 1
	}
}

func (m *MsgRawName) unpack() error {
	nameLen := uint16(0)
	ptrCount := uint8(0)

	for i := int(m.nameStart); i < len(m.m.msg); {
		// Compression pointer
		if m.m.msg[i]&0xC0 == 0xC0 {
			if ptrCount++; ptrCount > ptrLoopCount {
				m.lenNoPtr = 0
				return errPtrLoop
			}

			if m.lenNoPtr == 0 {
				m.lenNoPtr = uint8(i-int(m.nameStart)) + 2
			}

			if len(m.m.msg) == int(i)+1 {
				m.lenNoPtr = 0
				return errInvalidDNSName
			}

			i = int(uint16(m.m.msg[i]^0xC0)<<8 | uint16(m.m.msg[i+1]))
			continue
		}

		if m.m.msg[i] > 63 {
			m.lenNoPtr = 0
			return errInvalidDNSName
		}

		if nameLen++; nameLen > 255 {
			m.lenNoPtr = 0
			return errInvalidDNSName
		}

		if m.m.msg[i] == 0 {
			if m.lenNoPtr == 0 {
				m.lenNoPtr = uint8(i-int(m.nameStart)) + 1
			}

			return nil
		}

		nameLen += uint16(m.m.msg[i])
		i += int(m.m.msg[i]) + 1
	}

	m.lenNoPtr = 0
	return errInvalidDNSName
}

func (m *MsgRawName) AppendHumanName(a []byte) []byte {
	return nil
}

func (m *MsgRawName) NoFollowLen() uint8 {
	return m.lenNoPtr
}

func (r *MsgRawName) EqualString(name string) bool {
	return false
}

func (r *MsgRawName) EqualBytes(name []byte) bool {
	return false
}
