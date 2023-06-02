package dnsmsg

import (
	"errors"
	"strings"
)

const (
	maxDNSMessageLength = 1<<16 - 1
	maxEncodedNameLen   = 255
	maxLabelLength      = 63
)

var (
	errInvalidDNSMessage = errors.New("invalid dns message")
	errInvalidDNSName    = errors.New("invalid dns name encoding")
	errPtrLoop           = errors.New("dns compression pointer loop")
	errDNSMsgTooLong     = errors.New("too long dns message")
)

func NewParser(msg []byte) (Parser, error) {
	if len(msg) > maxDNSMessageLength {
		return Parser{}, errDNSMsgTooLong
	}

	return Parser{
		msg: msg,
	}, nil
}

type Parser struct {
	msg       []byte
	curOffset uint16
}

func (m *Parser) availMsgData() uint16 {
	return uint16(len(m.msg)) - uint16(m.curOffset)
}

func (m *Parser) Header() (Header, error) {
	var hdr Header
	if m.availMsgData() < headerLen {
		return hdr, errInvalidDNSMessage
	}

	hdr.unpack([headerLen]byte(m.msg[m.curOffset:]))
	m.curOffset += headerLen
	return hdr, nil
}

func (m *Parser) Question() (Question[ParserName], error) {
	q := Question[ParserName]{
		Name: ParserName{
			m:         m,
			nameStart: m.curOffset,
		},
	}

	offset, err := q.Name.unpack()
	if err != nil {
		return Question[ParserName]{}, err
	}

	tmpOffset := m.curOffset + offset

	if len(m.msg[tmpOffset:]) < 4 {
		return Question[ParserName]{}, errInvalidDNSMessage
	}

	q.Type = Type(unpackUint16(m.msg[tmpOffset : tmpOffset+2]))
	q.Class = Class(unpackUint16(m.msg[tmpOffset+2 : tmpOffset+4]))
	m.curOffset = tmpOffset + 4

	return q, nil
}

func (m *Parser) ResourceHeader() (ResourceHeader[ParserName], error) {
	q := ResourceHeader[ParserName]{
		Name: ParserName{
			m:         m,
			nameStart: m.curOffset,
		},
	}

	offset, err := q.Name.unpack()
	if err != nil {
		return ResourceHeader[ParserName]{}, err
	}

	tmpOffset := m.curOffset + offset

	if m.availMsgData() < 10 {
		return ResourceHeader[ParserName]{}, errInvalidDNSMessage
	}

	q.Type = Type(unpackUint16(m.msg[tmpOffset : tmpOffset+2]))
	q.Class = Class(unpackUint16(m.msg[tmpOffset+2 : tmpOffset+4]))
	q.TTL = unpackUint32(m.msg[tmpOffset+4 : tmpOffset+8])
	q.Length = unpackUint16(m.msg[tmpOffset+8 : tmpOffset+10])
	m.curOffset = tmpOffset + 10

	return q, nil
}

func (m *Parser) Skip(length int) error {
	if int(m.availMsgData()) < length {
		return errInvalidDNSMessage
	}
	m.curOffset += uint16(length)
	return nil
}

func (m *Parser) Name() (ParserName, error) {
	name := ParserName{
		m:         m,
		nameStart: m.curOffset,
	}

	offset, err := name.unpack()
	if err != nil {
		return ParserName{}, err
	}

	m.curOffset += offset
	return name, nil
}

func (m *Parser) RawResource(length uint16) ([]byte, error) {
	if len(m.msg[m.curOffset:]) < int(length) {
		return nil, errInvalidDNSMessage
	}

	msg := m.msg[m.curOffset : m.curOffset+length]
	m.curOffset += length

	return msg, nil
}

func (m *Parser) ResourceA(length uint16) (ResourceA, error) {
	if length != 4 || m.availMsgData() < 4 {
		return ResourceA{}, errInvalidDNSMessage
	}

	m.curOffset += 4
	return ResourceA{
		A: *(*[4]byte)(m.msg[m.curOffset-4 : m.curOffset]),
	}, nil
}

func (m *Parser) ResourceAAAA(length uint16) (ResourceAAAA, error) {
	if length != 16 || m.availMsgData() < 16 {
		return ResourceAAAA{}, errInvalidDNSMessage
	}

	m.curOffset += 16
	return ResourceAAAA{
		AAAA: *(*[16]byte)(m.msg[m.curOffset-16 : m.curOffset]),
	}, nil
}

func (m *Parser) ResourceCNAME(RDLength uint16) (ResourceCNAME[ParserName], error) {
	r := ResourceCNAME[ParserName]{
		CNAME: ParserName{
			m:         m,
			nameStart: m.curOffset,
		},
	}

	offset, err := r.CNAME.unpack()
	if err != nil {
		return ResourceCNAME[ParserName]{}, err
	}

	if offset != RDLength {
		return ResourceCNAME[ParserName]{}, errInvalidDNSMessage
	}

	m.curOffset += offset
	return r, nil
}

func (m *Parser) ResourceMX(RDLength uint16) (ResourceMX[ParserName], error) {
	r := ResourceMX[ParserName]{
		MX: ParserName{
			m:         m,
			nameStart: m.curOffset + 2,
		},
	}

	if m.availMsgData() < 2 {
		return ResourceMX[ParserName]{}, errInvalidDNSMessage
	}

	r.Pref = unpackUint16(m.msg[m.curOffset : m.curOffset+2])

	offset, err := r.MX.unpack()
	if err != nil {
		return ResourceMX[ParserName]{}, err
	}

	if offset != RDLength-2 {
		return ResourceMX[ParserName]{}, errInvalidDNSMessage
	}

	m.curOffset += offset + 2
	return r, nil
}

func (m *Parser) ResourceTXT(RDLength uint16) (ResourceTXT, error) {
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

const ptrLoopCount = 16

type ParserName struct {
	m         *Parser
	nameStart uint16
	rawLen    uint8
}

func (m *ParserName) RawLen() uint8 {
	return m.rawLen
}

// unpack parses the name, m.m and m.nameStart must be set accordingly
// before calling this method.
func (m *ParserName) unpack() (uint16, error) {
	var (
		// length of the raw name, without compression pointers.
		rawNameLen = uint16(0)

		// message offset, length up to the first compression pointer (if any, including it).
		offset = uint16(0)

		ptrCount = uint8(0)
	)

	for i := int(m.nameStart); i < len(m.m.msg); {
		// Compression pointer
		if m.m.msg[i]&0xC0 == 0xC0 {
			if ptrCount++; ptrCount > ptrLoopCount {
				return 0, errPtrLoop
			}

			if offset == 0 {
				offset = rawNameLen + 2
			}

			// Compression pointer is 2 bytes long.
			if len(m.m.msg) == int(i)+1 {
				return 0, errInvalidDNSName
			}

			i = int(uint16(m.m.msg[i]^0xC0)<<8 | uint16(m.m.msg[i+1]))
			continue
		}

		// Two leading bits are reserved, except for compression pointer (above).
		if m.m.msg[i]&0xC0 != 0 {
			return 0, errInvalidDNSName
		}

		if rawNameLen++; rawNameLen > maxEncodedNameLen {
			return 0, errInvalidDNSName
		}

		if m.m.msg[i] == 0 {
			if offset == 0 {
				offset = rawNameLen
			}
			m.rawLen = uint8(rawNameLen)
			return offset, nil
		}

		rawNameLen += uint16(m.m.msg[i])
		i += int(m.m.msg[i]) + 1
	}

	return 0, errInvalidDNSName
}

// Equal reports whether m and m2 represents the same name.
// It does not require identical internal representation of the name.
// Letters are compared in a case insensitive manner.
// m an m2 might be created using two different parsers.
func (m *ParserName) Equal(m2 *ParserName) bool {
	im1 := m.nameStart
	im2 := m2.nameStart

	for {
		// Resolve all compression pointers of m
		for m.m.msg[im1]&0xC0 == 0xC0 {
			im1 = uint16(m.m.msg[im1]^0xC0)<<8 | uint16(m.m.msg[im1+1])
		}

		// Resolve all compression pointers of m2
		for m2.m.msg[im2]&0xC0 == 0xC0 {
			im2 = uint16(m2.m.msg[im2]^0xC0)<<8 | uint16(m2.m.msg[im2+1])
		}

		// if we point to the same location in the same parser, then it is equal.
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

		if !caseInsensitiveEqual(m.m.msg[im1+1:im1+1+uint16(m.m.msg[im1])], m2.m.msg[im2+1:im2+1+uint16(m2.m.msg[im2])]) {
			return false
		}

		im1 += uint16(m.m.msg[im1]) + 1
		im2 += uint16(m2.m.msg[im2]) + 1
	}
}

// Equal reports whether m and m2 represents the same name.
func (m *ParserName) EqualName(m2 Name) bool {
	im1 := m.nameStart
	nameOffset := 0

	for {
		// Resolve all compression pointers of m
		for m.m.msg[im1]&0xC0 == 0xC0 {
			im1 = uint16(m.m.msg[im1]^0xC0)<<8 | uint16(m.m.msg[im1+1])
		}

		labelLength := m.m.msg[im1]

		if labelLength == 0 {
			return len(m2.n) == nameOffset || ((len(m2.n)-nameOffset) == 1 && m2.n[nameOffset] == '.')
		}

		im1++
		for _, v := range m.m.msg[im1 : im1+uint16(labelLength)] {
			if len(m2.n)-nameOffset == 0 {
				return false
			}

			char := m2.n[nameOffset]
			nameOffset++
			if char == '\\' {
				char = m2.n[nameOffset]
				nameOffset++
				if isDigit(char) {
					char, _ = decodeDDD([3]byte{char, m2.n[nameOffset], m2.n[nameOffset+1]})
					nameOffset += 2
				}
			}

			if !equalASCIICaseInsensitive(char, v) {
				return false
			}
		}

		if len(m2.n)-nameOffset != 0 {
			if m2.n[nameOffset] != '.' {
				return false
			}
			nameOffset++
		}

		im1 += uint16(labelLength)
	}
}

// len(a) must be caseInsensitiveEqual to len(b)
func caseInsensitiveEqual(a []byte, b []byte) bool {
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

// String returns the human name encoding of m. Dots inside the label
// (not separating labels) are escaped as '\.', slashes are encoded as '\\',
// other octets not in range (including) 0x21 through 0xFE are encoded using the \DDD syntax.
func (m *ParserName) String() string {
	builder := strings.Builder{}
	builder.Grow(int(m.RawLen() - 1))

	i := m.nameStart
	for {
		if m.m.msg[i]&0xC0 == 0xC0 {
			i = uint16(m.m.msg[i]^0xC0)<<8 | uint16(m.m.msg[i+1])
			continue
		}

		if m.m.msg[i] == 0 {
			if builder.Len() == 0 {
				builder.WriteByte('.')
			}
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

func (m *ParserName) appendRawName(raw []byte) []byte {
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
