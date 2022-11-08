package dnsmsg

import (
	"errors"
	"math"
	"strings"
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

func (m *Msg) MsgRawName() (MsgRawName, error) {
	name := MsgRawName{
		m:         m,
		nameStart: m.curOffset,
	}

	if err := name.unpack(); err != nil {
		return MsgRawName{}, err
	}

	m.curOffset += uint16(name.NoFollowLen())
	return name, nil
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

func (m *Msg) ResourceCNAME(RDLength uint16) (ResourceCNAME[MsgRawName], error) {
	r := ResourceCNAME[MsgRawName]{
		CNAME: MsgRawName{
			m:         m,
			nameStart: m.curOffset,
		},
	}

	err := r.CNAME.unpack()
	if err != nil {
		return ResourceCNAME[MsgRawName]{}, err
	}

	if uint16(r.CNAME.NoFollowLen()) != RDLength {
		return ResourceCNAME[MsgRawName]{}, errInvalidDNSMessage
	}

	m.curOffset += uint16(r.CNAME.NoFollowLen())
	return r, nil
}

func (m *Msg) ResourceMX(RDLength uint16) (ResourceMX[MsgRawName], error) {
	r := ResourceMX[MsgRawName]{
		MX: MsgRawName{
			m:         m,
			nameStart: m.curOffset + 2,
		},
	}

	if len(m.msg[m.curOffset:]) < 2 {
		return ResourceMX[MsgRawName]{}, errInvalidDNSMessage
	}

	r.Pref = unpackUint16(m.msg[m.curOffset : m.curOffset+2])

	err := r.MX.unpack()
	if err != nil {
		return ResourceMX[MsgRawName]{}, err
	}

	if uint16(r.MX.NoFollowLen()) != RDLength-2 {
		return ResourceMX[MsgRawName]{}, errInvalidDNSMessage
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
	rawLen   uint8
}

const ptrLoopCount = 16

// Equal reports whether m and m2 represents the same name.
// It does not require identical internal representation of the name.
// Letters are compared in a case insensitive manner.
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

// EqualRaw reports whether m and m2 represents the same name.
// m2 must be encoded using the RFC 1035 (section 3.1) name encoding,
// but without compression pointers. Letters are compared in a case insensitive manner.
func (m *MsgRawName) EqualRaw(m2 []byte) bool {
	im1 := m.nameStart
	im2 := uint16(0)

	for {
		// Resolve all (in a row) compression pointers of m
		for m.m.msg[im1]&0xC0 == 0xC0 {
			im1 = uint16(m.m.msg[im1]^0xC0)<<8 | uint16(m.m.msg[im1+1])
		}

		if len(m2) <= int(im2) {
			return false
		}

		// different label lengths
		if m.m.msg[im1] != m2[im2] {
			return false
		}

		if m.m.msg[im1] == 0 {
			return true
		}

		if uint16(len(m2[im2:])) < uint16(m2[im2])+1 {
			return false
		}

		if !equal(m.m.msg[im1+1:im1+1+uint16(m.m.msg[im1])], m2[im2+1:im2+1+uint16(m2[im2])]) {
			return false
		}

		im1 += uint16(m.m.msg[im1]) + 1
		im2 += uint16(m2[im2]) + 1
	}
}

//FIX: issues in EqualString/EqualBytes:

//TODO: we are assuming here that the name (m2) is a valid name, but it does not have to be
//TODO: decide how to handle that

// Equal reports whether m and a human encoded name m2 represents the same name.
// m2 must be a valid dns name. Special symbols (in m2) can be encoded using
// escaping techniques, like: '\.', '\\', '\046'. Letters are compared in a case insensitive manner.
func (m *MsgRawName) EqualString(m2 string) bool {
	return equalHumanEncodedName(m, m2)
}

// Equal reports whether m and a human encoded name m2 represents the same name.
// See EqualString for more information. Letters are compared in a case insensitive manner.
func (m *MsgRawName) EqualBytes(m2 []byte) bool {
	return equalHumanEncodedName(m, m2)
}

func equalHumanEncodedName[T []byte | string](m *MsgRawName, m2 T) bool {
	im1 := m.nameStart

	if len(m2) == 1 && m2[0] == '.' {
		for m.m.msg[im1]&0xC0 == 0xC0 {
			im1 = uint16(m.m.msg[im1]^0xC0)<<8 | uint16(m.m.msg[im1+1])
		}
		return m.m.msg[im1] == 0
	}

	for {
		// Resolve all (in a row) compression pointers of m
		for m.m.msg[im1]&0xC0 == 0xC0 {
			im1 = uint16(m.m.msg[im1]^0xC0)<<8 | uint16(m.m.msg[im1+1])
		}

		labelLength := m.m.msg[im1]

		if labelLength == 0 {
			return len(m2) == 0
		}

		if len(m2) < int(labelLength) {
			return false
		}

		rawLabel := m.m.msg[im1+1 : im1+1+uint16(labelLength)]
		m2Offset := 0

		for i := 0; i < len(rawLabel); i++ {
			var escaped bool

			if len(m2[m2Offset:]) == 0 {
				return false
			}

			char := m2[m2Offset]
			m2Offset++

			if char == '\\' {
				escaped = true

				if len(m2[m2Offset:]) == 0 {
					return false
				}

				nextChar := m2[m2Offset]
				m2Offset++

				switch {
				case nextChar >= '0' && nextChar <= '9':
					// RFC 1035:
					// \DDD where each D is a digit is the octet corresponding to
					// the decimal number described by DDD.  The resulting
					// octet is assumed to be text and is not checked for
					// special meaning.

					// invalid encoding
					if len(m2[m2Offset:]) < 2 {
						return false
					}

					//Second or third charecter is not a digit
					if m2[m2Offset] < '0' || m2[m2Offset] > '9' || m2[m2Offset+1] < '0' || m2[m2Offset+1] > '9' {
						return false
					}

					tmp := uint16(nextChar-'0')*100 + uint16(m2[m2Offset]-'0')*10 + uint16(m2[m2Offset+1]-'0')
					if tmp > math.MaxUint8 {
						return false
					}

					char = byte(tmp)
					m2Offset += 2
				default:
					// RFC 1035:
					// \X where X is any character other than a digit (0-9), is
					// used to quote that character so that its special meaning
					// does not apply.  For example, "\." can be used to place
					// a dot character in a label.
					char = nextChar
				}
			}

			// if char is not escaped, we can't have dot inside label
			if !escaped && char == '.' {
				return false
			}

			if !equalASCIICaseInsensitive(rawLabel[i], char) {
				return false
			}
		}

		im1 += uint16(m.m.msg[im1]) + 1

		if len(m2) > int(m2Offset) {
			if m2[m2Offset] != '.' {
				return false
			}

			m2 = m2[m2Offset+1:]
			continue
		}

		//set m2 to zero value
		var zero T
		m2 = zero
	}
}

// len(a) must be equal to len(b)
func equal[T1 []byte | string, T2 []byte | string](a T1, b T2) bool {
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
			m.rawLen = uint8(nameLen)
			return nil
		}

		nameLen += uint16(m.m.msg[i])
		i += int(m.m.msg[i]) + 1
	}

	m.lenNoPtr = 0
	return errInvalidDNSName
}

// String returns the human name encoding of m. Dots inside the label
// (not separating labels) are escaped as '\.', slashes are encoded as '\\',
// other octets not in range (including) 0x21 through 0xFE are encoded using the \DDD syntax.
func (m *MsgRawName) String() string {
	builder := strings.Builder{}
	builder.Grow(int(m.RawLen() - 1))

	i := m.nameStart
	for {
		if m.m.msg[i]&0xC0 == 0xC0 {
			i = uint16(m.m.msg[i]^0xC0)<<8 | uint16(m.m.msg[i+1])
			continue
		}

		if m.m.msg[i] == 0 {
			return builder.String()
		}

		for _, v := range m.m.msg[i+1 : i+uint16(m.m.msg[i])+1] {
			switch {
			case v == '.':
				builder.WriteString("\\.")
			case v == '\\':
				builder.WriteString("\\\\")
			case v < '!' || v > '~':
				builder.WriteByte('\\')
				builder.Write(toASCIIDecimal(v))
			default:
				builder.WriteByte(v)
			}
		}

		builder.WriteByte('.')
		i += uint16(m.m.msg[i]) + 1
	}
}

func toASCIIDecimal(v byte) []byte {
	var d [3]byte
	tmp := v / 100
	v -= tmp * 100
	d[0] = tmp + '0'
	tmp = v / 10
	v -= tmp * 10
	d[1] = tmp + '0'
	d[2] = v + '0'
	return d[:]
}

// Bytes does the same thing as String(), but it returns []byte
func (m *MsgRawName) Bytes() []byte {
	return m.AppendBytes(make([]byte, 0, m.RawLen()-1))
}

// AppendBytes, does the same thing as Bytes, but it appends.
func (m *MsgRawName) AppendBytes(buf []byte) []byte {
	i := m.nameStart
	for {
		if m.m.msg[i]&0xC0 == 0xC0 {
			i = uint16(m.m.msg[i]^0xC0)<<8 | uint16(m.m.msg[i+1])
			continue
		}

		if m.m.msg[i] == 0 {
			return buf
		}

		for _, v := range m.m.msg[i+1 : i+uint16(m.m.msg[i])+1] {
			switch {
			case v == '.':
				buf = append(buf, "\\."...)
			case v == '\\':
				buf = append(buf, "\\\\"...)
			case v < '!' || v > '~':
				buf = append(buf, "\\"...)
				buf = append(buf, toASCIIDecimal(v)...)
			default:
				buf = append(buf, v)
			}
		}

		buf = append(buf, '.')
		i += uint16(m.m.msg[i]) + 1
	}
}

// RawName returns the internal dns encoding (as defined in RFC 1035) of the m (without compression pointers)
func (m *MsgRawName) RawName() []byte {
	return m.AppendRawName(make([]byte, 0, m.RawLen()))
}

// AppendRawName, does the same thing as RawName, but it appends.
func (m *MsgRawName) AppendRawName(raw []byte) []byte {
	i := m.nameStart
	for {
		if m.m.msg[i]&0xC0 == 0xC0 {
			i = uint16(m.m.msg[i]^0xC0)<<8 | uint16(m.m.msg[i+1])
			continue
		}

		if m.m.msg[i] == 0 {
			return append(raw, 0)
		}

		raw = append(raw, m.m.msg[i:i+uint16(m.m.msg[i])+1]...)
		i += uint16(m.m.msg[i]) + 1
	}
}

func (m *MsgRawName) NoFollowLen() uint8 {
	return m.lenNoPtr
}

func (m *MsgRawName) RawLen() uint8 {
	return m.rawLen
}
