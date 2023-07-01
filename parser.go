package dnsmsg

import (
	"errors"
	"strings"
)

const (
	maxEncodedNameLen = 255
	maxLabelLength    = 63
)

var (
	// ErrSectionDone is returned by [Parser.Question] and [Parser.ResourceHeader] when
	// no more questions/resources are available to parse in the current section.
	ErrSectionDone = errors.New("parsing of current section done")

	errInvalidOperation = errors.New("invalid operation")

	errInvalidDNSMessage = errors.New("invalid dns message")
	errInvalidDNSName    = errors.New("invalid dns name encoding")
	errPtrLoop           = errors.New("compression pointer loop")
)

// Parse starts parsing a DNS message.
//
// This function sets the parsing section of the Parser to questions.
func Parse(msg []byte) (Parser, Header, error) {
	if len(msg) < headerLen {
		return Parser{}, Header{}, errInvalidDNSMessage
	}

	var hdr Header
	hdr.unpack([headerLen]byte(msg[:headerLen]))

	return Parser{
		msg:                   msg,
		curOffset:             headerLen,
		remainingQuestions:    hdr.QDCount,
		remainingAnswers:      hdr.ANCount,
		remainingAuthorites:   hdr.NSCount,
		remainingAddtitionals: hdr.ARCount,
	}, hdr, nil
}

// Parser is a incremental DNS parser.
//
// Parser can be copied to preserve the current parsing state.
type Parser struct {
	msg       []byte
	curOffset int

	nextResourceDataLength uint16
	nextResourceType       Type
	resourceData           bool
	curSection             section

	remainingQuestions    uint16
	remainingAnswers      uint16
	remainingAuthorites   uint16
	remainingAddtitionals uint16
}

// StartAnswers changes the parsing section from questions to answers.
//
// Returns error when the parsing of the current section is not yet completed.
func (p *Parser) StartAnswers() error {
	if p.curSection != sectionQuestions || p.resourceData || p.remainingQuestions != 0 {
		return errInvalidOperation
	}
	p.curSection = sectionAnswers
	return nil
}

// StartAuthorities changes the parsing section from answers to authorities.
//
// Returns error when the parsing of the current section is not yet completed.
func (p *Parser) StartAuthorities() error {
	if p.curSection != sectionAnswers || p.resourceData || p.remainingAnswers != 0 {
		return errInvalidOperation
	}
	p.curSection = sectionAuthorities
	return nil
}

// StartAdditionals changes the parsing section from authorities to additionals.
//
// Returns error when the parsing of the current section is not yet completed.
func (p *Parser) StartAdditionals() error {
	if p.curSection != sectionAuthorities || p.resourceData || p.remainingAuthorites != 0 {
		return errInvalidOperation
	}
	p.curSection = sectionAdditionals
	return nil
}

// End should be called after parsing every question and resource.
// It returns an error when there are remaining bytes after the end of the message.
//
// This method should only be called when parsing of all sections is completed, when
// there is nothing left to parse.
func (p *Parser) End() error {
	if p.resourceData || p.remainingQuestions != 0 || p.remainingAnswers != 0 ||
		p.remainingAuthorites != 0 || p.remainingAddtitionals != 0 {
		return errInvalidOperation
	}
	if len(p.msg) != p.curOffset {
		return errInvalidDNSMessage
	}
	return nil
}

// Question parses a single question.
// Returns [ErrSectionDone] when no more questions are available to parse.
//
// The parsing section must be set to questions.
func (m *Parser) Question() (Question[ParserName], error) {
	if m.curSection != sectionQuestions {
		return Question[ParserName]{}, errInvalidOperation
	}

	if m.remainingQuestions == 0 {
		return Question[ParserName]{}, ErrSectionDone
	}

	name, offset, err := m.unpackName(m.curOffset)
	if err != nil {
		return Question[ParserName]{}, err
	}

	tmpOffset := m.curOffset + int(offset)

	if len(m.msg)-tmpOffset < 4 {
		return Question[ParserName]{}, errInvalidDNSMessage
	}

	m.curOffset = tmpOffset + 4
	m.remainingQuestions--

	return Question[ParserName]{
		Name:  name,
		Type:  Type(unpackUint16(m.msg[tmpOffset : tmpOffset+2])),
		Class: Class(unpackUint16(m.msg[tmpOffset+2 : tmpOffset+4])),
	}, nil
}

// ResourceHeader parses a single header of a resource record.
//
// Every call to ResourceHeader must be followed by a appropriate
// Resource Data parsing method ([Parser.ResourceA], [Parser.ResourceAAAA],
// [Parser.ResourceCNAME], [Parser.ResourceMX], [Parser.RawResourceTXT]) depending
// on the returned [ResourceHeader] Type field or skipped by [Parser.SkipResourceData]
// (even when the [ResourceHeader] Length field is equal to zero).
//
// Returns [ErrSectionDone] when no more resources are available to parse in the
// current section.
//
// The parsing section must not be set to questions.
func (m *Parser) ResourceHeader() (ResourceHeader[ParserName], error) {
	if m.resourceData {
		return ResourceHeader[ParserName]{}, errInvalidOperation
	}

	var count *uint16
	switch m.curSection {
	case sectionAnswers:
		count = &m.remainingAnswers
	case sectionAuthorities:
		count = &m.remainingAuthorites
	case sectionAdditionals:
		count = &m.remainingAddtitionals
	default:
		return ResourceHeader[ParserName]{}, errInvalidOperation
	}

	if *count == 0 {
		return ResourceHeader[ParserName]{}, ErrSectionDone
	}

	name, offset, err := m.unpackName(m.curOffset)
	if err != nil {
		return ResourceHeader[ParserName]{}, err
	}

	tmpOffset := m.curOffset + int(offset)

	if len(m.msg)-tmpOffset < 10 {
		return ResourceHeader[ParserName]{}, errInvalidDNSMessage
	}

	hdr := ResourceHeader[ParserName]{
		Name:   name,
		Type:   Type(unpackUint16(m.msg[tmpOffset : tmpOffset+2])),
		Class:  Class(unpackUint16(m.msg[tmpOffset+2 : tmpOffset+4])),
		TTL:    unpackUint32(m.msg[tmpOffset+4 : tmpOffset+8]),
		Length: unpackUint16(m.msg[tmpOffset+8 : tmpOffset+10]),
	}

	m.nextResourceDataLength = hdr.Length
	m.nextResourceType = hdr.Type
	m.resourceData = true

	m.curOffset = tmpOffset + 10
	*count--

	return hdr, nil
}

// ResourceA parses a single A resouce data.
//
// This method can only be used after [Parser.ResourceHeader]
// returns a [ResourceHeader] with a Type field equal to [TypeA].
func (m *Parser) ResourceA() (ResourceA, error) {
	if !m.resourceData || m.nextResourceType != TypeA {
		return ResourceA{}, errInvalidOperation
	}
	if m.nextResourceDataLength != 4 || len(m.msg)-m.curOffset < 4 {
		return ResourceA{}, errInvalidDNSMessage
	}
	a := [4]byte(m.msg[m.curOffset:])
	m.resourceData = false
	m.curOffset += 4
	return ResourceA{
		A: a,
	}, nil
}

// ResourceAAAA parses a single AAAA resouce data.
//
// This method can only be used after [Parser.ResourceHeader]
// returns a [ResourceHeader] with a Type field equal to [TypeAAAA].
func (m *Parser) ResourceAAAA() (ResourceAAAA, error) {
	if !m.resourceData || m.nextResourceType != TypeAAAA {
		return ResourceAAAA{}, errInvalidOperation
	}
	if m.nextResourceDataLength != 16 || len(m.msg)-m.curOffset < 16 {
		return ResourceAAAA{}, errInvalidDNSMessage
	}
	aaaa := [16]byte(m.msg[m.curOffset:])
	m.resourceData = false
	m.curOffset += 16
	return ResourceAAAA{
		AAAA: aaaa,
	}, nil
}

// ResourceCNAME parses a single CNAME resouce data.
//
// This method can only be used after [Parser.ResourceHeader]
// returns a [ResourceHeader] with a Type field equal to [TypeCNAME].
func (m *Parser) ResourceCNAME() (ResourceCNAME[ParserName], error) {
	if !m.resourceData || m.nextResourceType != TypeCNAME {
		return ResourceCNAME[ParserName]{}, errInvalidOperation
	}

	name, offset, err := m.unpackName(m.curOffset)
	if err != nil {
		return ResourceCNAME[ParserName]{}, err
	}

	if offset != m.nextResourceDataLength {
		return ResourceCNAME[ParserName]{}, errInvalidDNSMessage
	}

	m.resourceData = false
	m.curOffset += int(offset)
	return ResourceCNAME[ParserName]{name}, nil
}

// ResourceMX parses a single MX resouce data.
//
// This method can only be used after [Parser.ResourceHeader]
// returns a [ResourceHeader] with a Type field equal to [TypeMX].
func (m *Parser) ResourceMX() (ResourceMX[ParserName], error) {
	if !m.resourceData || m.nextResourceType != TypeMX {
		return ResourceMX[ParserName]{}, errInvalidOperation
	}

	if len(m.msg)-m.curOffset < 2 {
		return ResourceMX[ParserName]{}, errInvalidDNSMessage
	}

	pref := unpackUint16(m.msg[m.curOffset:])
	name, offset, err := m.unpackName(m.curOffset + 2)
	if err != nil {
		return ResourceMX[ParserName]{}, err
	}

	if m.nextResourceDataLength != offset+2 {
		return ResourceMX[ParserName]{}, errInvalidDNSMessage
	}

	m.resourceData = false
	m.curOffset += int(m.nextResourceDataLength)
	return ResourceMX[ParserName]{
		Pref: pref,
		MX:   name,
	}, nil
}

// RawResourceTXT parses a single TXT resouce data.
//
// This method can only be used after [Parser.ResourceHeader]
// returns a [ResourceHeader] with a Type field equal to [TypeTXT].
func (m *Parser) RawResourceTXT() (RawResourceTXT, error) {
	if !m.resourceData || m.nextResourceType != TypeTXT {
		return RawResourceTXT{}, errInvalidOperation
	}

	if len(m.msg)-m.curOffset < int(m.nextResourceDataLength) {
		return RawResourceTXT{}, errInvalidDNSMessage
	}

	r := RawResourceTXT{m.msg[m.curOffset : m.curOffset+int(m.nextResourceDataLength)]}
	if !r.isValid() {
		return RawResourceTXT{}, errInvalidDNSMessage
	}

	m.resourceData = false
	m.curOffset += int(m.nextResourceDataLength)
	return r, nil
}

// SkipResourceData skips the resource data, without parsing it in any way.
//
// This method can only be called after calling the [Parser.ResourceHeader] method.
func (m *Parser) SkipResourceData() error {
	if !m.resourceData {
		return errInvalidOperation
	}
	if len(m.msg)-m.curOffset < int(m.nextResourceDataLength) {
		return errInvalidDNSMessage
	}
	m.curOffset += int(m.nextResourceDataLength)
	m.resourceData = false
	return nil
}

func (m *Parser) unpackName(offset int) (ParserName, uint16, error) {
	n := ParserName{m: m, nameStart: offset}
	off, err := n.unpack()
	return n, off, err
}

const ptrLoopCount = 16

type ParserName struct {
	m *Parser

	nameStart  int
	rawLen     uint8
	compressed bool
}

func (m *ParserName) Compressed() bool {
	return m.compressed
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
			m.compressed = true
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
			im1 = int(m.m.msg[im1]^0xC0)<<8 | int(m.m.msg[im1+1])
		}

		// Resolve all compression pointers of m2
		for m2.m.msg[im2]&0xC0 == 0xC0 {
			im2 = int(m2.m.msg[im2]^0xC0)<<8 | int(m2.m.msg[im2+1])
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

		if !caseInsensitiveEqual(m.m.msg[im1+1:im1+1+int(m.m.msg[im1])], m2.m.msg[im2+1:im2+1+int(m2.m.msg[im2])]) {
			return false
		}

		im1 += int(m.m.msg[im1]) + 1
		im2 += int(m2.m.msg[im2]) + 1
	}
}

// EqualName reports whether m and m2 represents the same name.
func (m *ParserName) EqualName(m2 Name) bool {
	return m.equalName(m2, false)
}

func (m *ParserName) equalName(m2 Name, updateNameStart bool) bool {
	im1 := m.nameStart
	nameOffset := 0

	for {
		// Resolve all compression pointers of m
		for m.m.msg[im1]&0xC0 == 0xC0 {
			im1 = int(m.m.msg[im1]^0xC0)<<8 | int(m.m.msg[im1+1])
		}

		labelLength := m.m.msg[im1]

		if labelLength == 0 {
			return len(m2.n) == nameOffset || ((len(m2.n)-nameOffset) == 1 && m2.n[nameOffset] == '.')
		}

		if updateNameStart && len(m2.n)-nameOffset == 0 {
			m.nameStart = im1
			return true
		}

		im1++
		for _, v := range m.m.msg[im1 : im1+int(labelLength)] {
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

		im1 += int(labelLength)
	}
}

// EqualSearchName reports whether m and m2 represents the same name.
func (m *ParserName) EqualSearchName(m2 SearchName) bool {
	c := *m
	return c.equalName(m2.name, true) && c.equalName(m2.suffix, false)
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
			i = int(m.m.msg[i]^0xC0)<<8 | int(m.m.msg[i+1])
			continue
		}

		if m.m.msg[i] == 0 {
			if builder.Len() == 0 {
				builder.WriteByte('.')
			}
			return builder.String()
		}

		for _, v := range m.m.msg[i+1 : i+int(m.m.msg[i])+1] {
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
		i += int(m.m.msg[i]) + 1
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
			i = int(m.m.msg[i]^0xC0)<<8 | int(m.m.msg[i+1])
			continue
		}

		if m.m.msg[i] == 0 {
			return append(raw, 0)
		}

		raw = append(raw, m.m.msg[i:i+int(m.m.msg[i])+1]...)
		i += int(m.m.msg[i]) + 1
	}
}

func (m *ParserName) appendRawNameNoInline(raw []byte) []byte {
	return m.appendRawName(raw)
}

func (m *ParserName) AsRawName() RawName {
	return m.appendRawNameNoInline(make([]byte, 0, maxEncodedNameLen))
}
