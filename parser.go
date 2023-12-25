package dnsmsg

import (
	"errors"
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

// Parser is an incremental DNS message parser.
//
// Internally the Parser contains a parsing section field, that can be changed
// using one of these methods: [Parser.StartAnswers], [Parser.StartAuthorities], [Parser.StartAdditionals].
// By default the parsing section is set to questions, this allows parsing the questions section by the
// use of the [Parser.Question] method.
// After changing the parsing section (using one of the Start* methods described above) the [Parser.ResourceHeader]
// method in conjunction with resource parsing methods [Parser.ResourceA], [Parser.ResourceAAAA], [Parser.ResourceNS],
// [Parser.ResourceCNAME], [Parser.ResourceSOA], [Parser.ResourcePTR] [Parser.ResourceMX], [Parser.RawResourceTXT],
// [Parser.SkipResourceData] or [Parser.RDParser] can be used to parse the resource data.
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

// SkipQuestions skips all questions.
//
// The parsing section must be set to questions.
func (p *Parser) SkipQuestions() error {
	for {
		_, err := p.Question()
		if err != nil {
			if err == ErrSectionDone {
				return nil
			}
			return err
		}
	}
}

// SkipResources skips all resources in the current parsing section.
//
// The parsing section must not be set to questions.
func (p *Parser) SkipResources() error {
	for {
		_, err := p.ResourceHeader()
		if err != nil {
			if err == ErrSectionDone {
				return nil
			}
			return err
		}

		if err := p.SkipResourceData(); err != nil {
			return err
		}
	}
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
func (m *Parser) Question() (Question, error) {
	if m.curSection != sectionQuestions {
		return Question{}, errInvalidOperation
	}

	if m.remainingQuestions == 0 {
		return Question{}, ErrSectionDone
	}

	var name Name
	offset, err := name.unpack(m.msg, m.curOffset)
	if err != nil {
		return Question{}, err
	}

	tmpOffset := m.curOffset + int(offset)

	if len(m.msg)-tmpOffset < 4 {
		return Question{}, errInvalidDNSMessage
	}

	m.curOffset = tmpOffset + 4
	m.remainingQuestions--

	return Question{
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
func (m *Parser) ResourceHeader() (ResourceHeader, error) {
	if m.resourceData {
		return ResourceHeader{}, errInvalidOperation
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
		return ResourceHeader{}, errInvalidOperation
	}

	if *count == 0 {
		return ResourceHeader{}, ErrSectionDone
	}

	var name Name
	offset, err := name.unpack(m.msg, m.curOffset)
	if err != nil {
		return ResourceHeader{}, err
	}

	tmpOffset := m.curOffset + int(offset)

	if len(m.msg)-tmpOffset < 10 {
		return ResourceHeader{}, errInvalidDNSMessage
	}

	hdr := ResourceHeader{
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

// ResourceNS parses a single NS resouce data.
//
// This method can only be used after [Parser.ResourceHeader]
// returns a [ResourceHeader] with a Type field equal to [TypeNS].
func (m *Parser) ResourceNS() (ResourceNS, error) {
	if !m.resourceData || m.nextResourceType != TypeNS {
		return ResourceNS{}, errInvalidOperation
	}

	var ns Name
	offset, err := ns.unpack(m.msg, m.curOffset)
	if err != nil {
		return ResourceNS{}, err
	}

	if offset != m.nextResourceDataLength {
		return ResourceNS{}, errInvalidDNSMessage
	}

	m.resourceData = false
	m.curOffset += int(offset)
	return ResourceNS{ns}, nil
}

// ResourceCNAME parses a single CNAME resouce data.
//
// This method can only be used after [Parser.ResourceHeader]
// returns a [ResourceHeader] with a Type field equal to [TypeCNAME].
func (m *Parser) ResourceCNAME() (ResourceCNAME, error) {
	if !m.resourceData || m.nextResourceType != TypeCNAME {
		return ResourceCNAME{}, errInvalidOperation
	}

	var cname Name
	offset, err := cname.unpack(m.msg, m.curOffset)
	if err != nil {
		return ResourceCNAME{}, err
	}

	if offset != m.nextResourceDataLength {
		return ResourceCNAME{}, errInvalidDNSMessage
	}

	m.resourceData = false
	m.curOffset += int(offset)
	return ResourceCNAME{cname}, nil
}

// ResourceSOA parses a single SOA resouce data.
//
// This method can only be used after [Parser.ResourceHeader]
// returns a [ResourceHeader] with a Type field equal to [TypeSOA].
func (m *Parser) ResourceSOA() (ResourceSOA, error) {
	if !m.resourceData || m.nextResourceType != TypeSOA {
		return ResourceSOA{}, errInvalidOperation
	}

	var ns Name
	var mbox Name

	tmpOffset := m.curOffset
	offset, err := ns.unpack(m.msg, tmpOffset)
	if err != nil {
		return ResourceSOA{}, err
	}
	tmpOffset += int(offset)

	offset, err = mbox.unpack(m.msg, tmpOffset)
	if err != nil {
		return ResourceSOA{}, err
	}
	tmpOffset += int(offset)

	if len(m.msg)-tmpOffset < 20 {
		return ResourceSOA{}, errInvalidDNSMessage
	}

	serial := unpackUint32(m.msg[tmpOffset:])
	refresh := unpackUint32(m.msg[tmpOffset+4:])
	retry := unpackUint32(m.msg[tmpOffset+8:])
	expire := unpackUint32(m.msg[tmpOffset+12:])
	minimum := unpackUint32(m.msg[tmpOffset+16:])
	tmpOffset += 20

	if tmpOffset-m.curOffset != int(m.nextResourceDataLength) {
		return ResourceSOA{}, errInvalidDNSMessage
	}

	m.resourceData = false
	m.curOffset = tmpOffset
	return ResourceSOA{
		NS:      ns,
		Mbox:    mbox,
		Serial:  serial,
		Refresh: refresh,
		Retry:   retry,
		Expire:  expire,
		Minimum: minimum,
	}, nil
}

// ResourcePTR parses a single PTR resouce data.
//
// This method can only be used after [Parser.ResourceHeader]
// returns a [ResourceHeader] with a Type field equal to [TypePTR].
func (m *Parser) ResourcePTR() (ResourcePTR, error) {
	if !m.resourceData || m.nextResourceType != TypePTR {
		return ResourcePTR{}, errInvalidOperation
	}

	var ptr Name
	offset, err := ptr.unpack(m.msg, m.curOffset)
	if err != nil {
		return ResourcePTR{}, err
	}

	if offset != m.nextResourceDataLength {
		return ResourcePTR{}, errInvalidDNSMessage
	}

	m.resourceData = false
	m.curOffset += int(offset)
	return ResourcePTR{ptr}, nil
}

// ResourceMX parses a single MX resouce data.
//
// This method can only be used after [Parser.ResourceHeader]
// returns a [ResourceHeader] with a Type field equal to [TypeMX].
func (m *Parser) ResourceMX() (ResourceMX, error) {
	if !m.resourceData || m.nextResourceType != TypeMX {
		return ResourceMX{}, errInvalidOperation
	}

	if len(m.msg)-m.curOffset < 2 {
		return ResourceMX{}, errInvalidDNSMessage
	}

	pref := unpackUint16(m.msg[m.curOffset:])

	var mx Name
	offset, err := mx.unpack(m.msg, m.curOffset+2)
	if err != nil {
		return ResourceMX{}, err
	}

	if m.nextResourceDataLength != offset+2 {
		return ResourceMX{}, errInvalidDNSMessage
	}

	m.resourceData = false
	m.curOffset += int(m.nextResourceDataLength)
	return ResourceMX{
		Pref: pref,
		MX:   mx,
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

// RDParser is a resource data parser used to parse custom resources.
type RDParser struct {
	m         *Parser
	offset    int
	maxOffset int
}

// Length returns the remaining bytes in the resource data.
func (p *RDParser) Length() uint16 {
	return uint16(p.maxOffset - p.offset)
}

// End checks if there is any remaining data in the resource data being parsed.
// It is used to ensure that the entire resource data has been successfully parsed and
// no unexpected data remains.
func (p *RDParser) End() error {
	if p.Length() == 0 {
		return nil
	}
	return errInvalidDNSMessage
}

// Name parses a single DNS name.
func (p *RDParser) Name() (Name, error) {
	var n Name
	offset, err := n.unpack(p.m.msg, p.offset)
	if err != nil {
		return Name{}, err
	}
	if p.offset+int(offset) > p.maxOffset {
		return Name{}, errInvalidDNSMessage
	}
	p.offset += int(offset)
	return n, nil
}

// AllBytes returns all remaining bytes in p.
// The length of the byte slice is equal to [RDParser.Length].
//
// The returned slice references the underlying message pased to [Parse].
func (p *RDParser) AllBytes() []byte {
	offset := p.offset
	p.offset = p.maxOffset
	return p.m.msg[offset:p.maxOffset]
}

// Bytes returns a n-length slice, errors when [RDParser.Length} < n.
//
// The returned slice references the underlying message pased to [Parse].
func (p *RDParser) Bytes(n int) ([]byte, error) {
	if p.offset+n > p.maxOffset {
		return nil, errInvalidDNSMessage
	}
	offset := p.offset
	p.offset += n
	return p.m.msg[offset:p.offset], nil
}

// Uint8 parses a single uint8 value.
// It requires at least one byte to be available in the RDParser to successfully parse.
func (p *RDParser) Uint8() (uint8, error) {
	if p.offset+1 > p.maxOffset {
		return 0, errInvalidDNSMessage
	}
	offset := p.offset
	p.offset++
	return p.m.msg[offset], nil
}

// Uint16 parses a single Big-Endian uint16 value.
// It requires at least two bytes to be available in the RDParser to successfully parse.
func (p *RDParser) Uint16() (uint16, error) {
	if p.offset+2 > p.maxOffset {
		return 0, errInvalidDNSMessage
	}
	offset := p.offset
	p.offset += 2
	return unpackUint16(p.m.msg[offset:]), nil
}

// Uint32 parses a single Big-Endian uint32 value.
// It requires at least four bytes to be available in the RDParser to successfully parse.
func (p *RDParser) Uint32() (uint32, error) {
	if p.offset+4 > p.maxOffset {
		return 0, errInvalidDNSMessage
	}
	offset := p.offset
	p.offset += 4
	return unpackUint32(p.m.msg[offset:]), nil
}

// Uint64 parses a single Big-Endian uint64 value.
// It requires at least eight bytes to be available in the RDParser to successfully parse.
func (p *RDParser) Uint64() (uint64, error) {
	if p.offset+8 > p.maxOffset {
		return 0, errInvalidDNSMessage
	}
	offset := p.offset
	p.offset += 8
	return unpackUint64(p.m.msg[offset:]), nil
}

// RDParser craeates a new [RDParser], used for parsing custom resource data.
func (m *Parser) RDParser() (RDParser, error) {
	if !m.resourceData {
		return RDParser{}, errInvalidOperation
	}
	if len(m.msg)-m.curOffset < int(m.nextResourceDataLength) {
		return RDParser{}, errInvalidDNSMessage
	}
	offset := m.curOffset
	m.curOffset += int(m.nextResourceDataLength)
	m.resourceData = false
	return RDParser{
		m:         m,
		offset:    offset,
		maxOffset: m.curOffset,
	}, nil
}
