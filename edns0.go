package dnsmsg

import (
	"errors"
	"math"
)

const (
	rCodeBits = 4
	rCodeMask = (1 << rCodeBits) - 1
)

// ExtendedRCode is an extended RCode.
// To create an ExtendedRCode from [PartialExtendedRCode] and [RCode] use [NewExtendedRCode].
type ExtendedRCode uint16

// NewExtendedRCode combines the [PartialExtendedRCode] and [RCode] into an [ExtendedRCode]
func NewExtendedRCode(partial PartialExtendedRCode, rcode RCode) ExtendedRCode {
	return ExtendedRCode((uint16(partial) << rCodeBits) | uint16(rcode))
}

// PartialExtendedRCode returns the part of the ExtendedRCode used in [EDNS0Header]
func (e ExtendedRCode) PartialExtendedRCode() PartialExtendedRCode {
	return PartialExtendedRCode(uint8(e >> rCodeBits))
}

// PartialExtendedRCode returns the part of the ExtendedRCode used in [Header]
func (e ExtendedRCode) RCode() RCode {
	return RCode(uint8(e & rCodeMask))
}

// ExtendedFlags are an extended flags used in EDNS(0).
type ExtendedFlags uint16

const (
	// EDNS0HeaderEncodingLength is a length required to encode a resource with a resource header
	// created by [EDNS0Header.AsResourceHeader] and zero-length resource data.
	EDNS0HeaderEncodingLength = 1 + 10

	// ResourceOPTOptionMetadataLength represents the size of an "metadata"
	// (option code and length).of an EDNS(0) options.
	ResourceOPTOptionMetadataLength = 4
)

// PartialExtendedRCode represents a part of an [ExtendedRCode] used by [EDNS0Header].
// It can be combined with [RCode] using the [NewExtendedRCode] to create an [ExtendedRCode].
type PartialExtendedRCode uint8

// EDNS0Header represents a [ResourceHeader] interpreted as an EDNS(0) header.
type EDNS0Header struct {
	Payload              uint16
	PartialExtendedRCode PartialExtendedRCode
	Version              uint8
	ExtendedFlags        ExtendedFlags
}

// AsResourceHeader converts [EDNS0Header] into a [ResourceHeader].
func (e EDNS0Header) AsResourceHeader() ResourceHeader {
	return ResourceHeader{
		Name:  Name{Length: 1},
		Type:  TypeOPT,
		Class: Class(e.Payload),
		TTL:   uint32(e.PartialExtendedRCode)<<24 | uint32(e.Version)<<16 | uint32(e.ExtendedFlags),
	}
}

var errInvalidEDNS0Header = errors.New("invalid EDNS(0) header")

// AsEDNS0Header parses the ResourceHeader into an [EDNS0Header].
//
// This function should only be called when the h.Type is equal to [TypeOPT].
func (h *ResourceHeader) AsEDNS0Header() (EDNS0Header, error) {
	if h.Type != TypeOPT {
		return EDNS0Header{}, errInvalidOperation
	}

	if h.Name.Length != 1 {
		return EDNS0Header{}, errInvalidEDNS0Header
	}

	return EDNS0Header{
		Payload:              uint16(h.Class),
		PartialExtendedRCode: PartialExtendedRCode(uint8(h.TTL >> 24)),
		Version:              uint8(h.TTL >> 16),
		ExtendedFlags:        ExtendedFlags(uint16(h.TTL)),
	}, nil
}

// EDNS0OptionCode is an option code of an EDNS(0) option.
type EDNS0OptionCode uint16

const (
	EDNS0OptionCodeClientSubnet     EDNS0OptionCode = 8
	EDNS0OptionCodeCookie           EDNS0OptionCode = 10
	EDNS0OptionCodeExtendedDNSError EDNS0OptionCode = 15
)

// AddressFamily is an address family, currently used by [EDNS0ClientSubnet].
//
// Defined in [Address_Family_Numbers].
//
// [Address_Family_Numbers]: http://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
type AddressFamily uint8

const (
	AddressFamilyIPv4 AddressFamily = 1
	AddressFamilyIPv6 AddressFamily = 2
)

// EDNS0ClientSubnet ia an EDNS(0) option defined in RFC 7871.
type EDNS0ClientSubnet struct {
	Family             AddressFamily
	SourcePrefixLength uint8
	ScopePrefixLength  uint8
	Address            []byte
}

// EncodingLength return the encoding length of the option.
//
// Note: It does not include the "metadata" (option code and length).
func (o *EDNS0ClientSubnet) EncodingLength() int {
	return 3 + len(o.Address)
}

func (o *EDNS0ClientSubnet) optionEncodingLength() int { return o.EncodingLength() }

// EDNS0Cookie ia an EDNS(0) option defined in RFC 7873.
type EDNS0Cookie struct {
	ClientCookie [8]byte
	ServerCookie [32]byte

	// ServerCookieAdditionalLength represents the amount of additional ServerCookie bytes
	// that are used as an server cookie. When set to 0, only 8 leading bytes are used.
	// The maximum value of ServerCookieAdditionalLength is 24, which implies that all bytes
	// in ServerCookie are used as a server cookie.
	ServerCookieAdditionalLength uint8
}

// EncodingLength return the encoding length of the option.
//
// Note: It does not include the "metadata" (option code and length).
func (o *EDNS0Cookie) EncodingLength() int {
	return len(o.ClientCookie) + int((o.ServerCookieAdditionalLength+8)%uint8(len(o.ServerCookie)))
}

func (o *EDNS0Cookie) optionEncodingLength() int { return o.EncodingLength() }

type ExtendedDNSErrorCode uint16

// EDNS0ExtendedDNSError is an EDNS(0) option defined in RFC 8914.
type EDNS0ExtendedDNSError struct {
	InfoCode  ExtendedDNSErrorCode
	ExtraText []byte
}

// EncodingLength return the encoding length of the option.
//
// Note: It does not include the "metadata" (option code and length).
func (o *EDNS0ExtendedDNSError) EncodingLength() int {
	return 2 + len(o.ExtraText)
}

func (o *EDNS0ExtendedDNSError) optionEncodingLength() int { return o.EncodingLength() }

type EDNS0Option interface {
	optionEncodingLength() int
}

type ResourceOPT struct {
	Options []EDNS0Option
}

// EncodingLength returns the DNS encoding length of the resource.
//
// Note: The length does not include the resource header size, the size of the resource header
// is most likely to be equal to [EDNS0HeaderEncodingLength].
func (r *ResourceOPT) EncodingLength() int {
	var length int
	for _, opt := range r.Options {
		length += ResourceOPTOptionMetadataLength + opt.optionEncodingLength()
	}
	return length
}

// ResourceOPT appends a single OPT resource.
// It errors when the amount of resources in the current section is equal to 65535.
//
// The building section must NOT be set to questions, otherwise it panics.
func (b *Builder) ResourceOPT(hdr ResourceHeader, opt ResourceOPT) error {
	optb, err := b.ResourceOPTBuilder(hdr)
	if err != nil {
		return err
	}
	for _, opt := range opt.Options {
		var err error
		switch opt := opt.(type) {
		case *EDNS0ClientSubnet:
			err = optb.ClientSubnet(*opt)
		case *EDNS0Cookie:
			err = optb.Cookie(*opt)
		case *EDNS0ExtendedDNSError:
			err = optb.ExtendedDNSError(*opt)
		}
		if err != nil {
			optb.Remove()
			return err
		}
	}
	optb.End()
	return nil
}

// ResourceOPTBuilder creates a new instance of [ResourceOPTBuilder].
// It errors when the amount of resources in the current section is equal to 65535.
//
// After creating the [ResourceOPTBuilder], all resource appending methods shouldn't be used
// on the Builder until you call [ResourceOPTBuilder.End] or [ResourceOPTBuilder.Remove].
//
// The building section must NOT be set to questions, otherwise it panics.
func (b *Builder) ResourceOPTBuilder(hdr ResourceHeader) (ResourceOPTBuilder, error) {
	hdr.Type = TypeOPT
	fixup, hdrOffset, c, err := b.appendHeaderWithLengthFixupNoInc(hdr, b.maxBufSize)
	if err != nil {
		return ResourceOPTBuilder{}, err
	}
	b.curSection |= sectionDetachedMask
	b.fakeBufSize = hdrOffset
	return ResourceOPTBuilder{
		b:         b,
		count:     c,
		hdrOffset: hdrOffset,
		fixup:     fixup,
	}, nil
}

// ResourceOPTBuilder is a builder for building OPT resource options.
//
// Once the entire resource data has been created, the [ResourceOPTBuilder.End] method needs to be called.
type ResourceOPTBuilder struct {
	_ noCopy

	b          *Builder
	count      *uint16
	hdrOffset  int
	fixup      headerLengthFixup
	fakeLength uint16
}

// Length returns the current length of the resource data in bytes.
func (b *ResourceOPTBuilder) Length() uint16 {
	if b.fakeLength != 0 {
		return b.fakeLength - 4
	}
	return b.length()
}

func (b *ResourceOPTBuilder) length() uint16 {
	return uint16(b.fixup.rDataLength(b.b))
}

func (b *ResourceOPTBuilder) callValid() {
	if b.fakeLength != 0 {
		panic("dnsmsg: invalid usage of the ResourceOPTBuilder, it is currently detached to a EDNS0OptionBuilder, call End() or Remove() before on the EDNS0OptionBuilder")
	}
}

// End finalizes the resource data building process and reflects the changes made using the ResourceOPTBuilder in the Builder.
// This method must be called after writing the entire resource data is done.
// Attempting to use the ResourceOPTBuilder after calling End might lead to panics.
func (b *ResourceOPTBuilder) End() {
	b.callValid()
	b.b.fakeBufSize = math.MaxInt
	b.b.curSection &= ^sectionDetachedMask
	b.fixup.fixup(b.b)
	*b.count++
	b.b = nil
}

// Remove removes the resource from the message.
// Attempting to use the ResourceOPTBuilder after calling Remove might lead to panics.
func (b *ResourceOPTBuilder) Remove() {
	b.callValid()
	b.b.fakeBufSize = math.MaxInt
	b.b.curSection &= ^sectionDetachedMask
	b.b.nb.removeNamesFromCompressionMap(b.b.headerStartOffset, b.hdrOffset)
	b.b.buf = b.b.buf[:b.hdrOffset]
}

func (b *ResourceOPTBuilder) appendOptionMetadata(code EDNS0OptionCode, encodingLength int) error {
	b.callValid()
	if b.fixup.rDataLength(b.b)+encodingLength+4 > math.MaxUint16 {
		return errResourceTooLong
	}
	if len(b.b.buf)+encodingLength+4 > b.b.maxBufSize {
		return ErrTruncated
	}
	b.b.buf = appendUint16(b.b.buf, uint16(code))
	b.b.buf = appendUint16(b.b.buf, uint16(encodingLength))
	return nil
}

// ClientSubnet append a single client subnet option to the OPT resource.
func (b *ResourceOPTBuilder) ClientSubnet(opt EDNS0ClientSubnet) error {
	if err := b.appendOptionMetadata(EDNS0OptionCodeClientSubnet, opt.EncodingLength()); err != nil {
		return err
	}
	b.b.buf = append(b.b.buf, uint8(opt.Family), opt.SourcePrefixLength, opt.ScopePrefixLength)
	b.b.buf = append(b.b.buf, opt.Address...)
	return nil
}

// Cookie append a single cookie option to the OPT resource.
func (b *ResourceOPTBuilder) Cookie(opt EDNS0Cookie) error {
	if err := b.appendOptionMetadata(EDNS0OptionCodeCookie, opt.EncodingLength()); err != nil {
		return err
	}
	b.b.buf = append(b.b.buf, opt.ClientCookie[:]...)
	b.b.buf = append(b.b.buf, opt.ServerCookie[:(opt.ServerCookieAdditionalLength+8)%uint8(len(opt.ServerCookie))]...)
	return nil
}

// ExtendedDNSError appends a single extended dns error option to the OPT resource.
func (b *ResourceOPTBuilder) ExtendedDNSError(opt EDNS0ExtendedDNSError) error {
	if err := b.appendOptionMetadata(EDNS0OptionCodeExtendedDNSError, opt.EncodingLength()); err != nil {
		return err
	}
	b.b.buf = appendUint16(b.b.buf, uint16(opt.InfoCode))
	b.b.buf = append(b.b.buf, opt.ExtraText...)
	return nil
}

// OptionBuilder creates a new [EDNS0OptionBuilder] used for building custom OPT options.
//
// After creating the [EDNS0OptionBuilder], all option appending methods shouldn`t be used
// on the ResourceOPTBuilder until you call [EDNS0OptionBuilder.End] or [EDNS0OptionBuilder.Remove].
func (b *ResourceOPTBuilder) OptionBuilder(code EDNS0OptionCode) (EDNS0OptionBuilder, error) {
	offset := len(b.b.buf)
	if err := b.appendOptionMetadata(code, 0); err != nil {
		return EDNS0OptionBuilder{}, err
	}
	b.fakeLength = b.length()
	return EDNS0OptionBuilder{
		b:              b,
		optStartOffset: offset,
	}, nil
}

// ResourceOPTBuilder is a builder for building OPT resource option.
//
// Once the entire resource data has been created, the [EDNS0OptionBuilder.End] method needs to be called.
type EDNS0OptionBuilder struct {
	_ noCopy

	b              *ResourceOPTBuilder
	optStartOffset int
}

// Length returns the current length of the option in bytes.
func (b *EDNS0OptionBuilder) Length() uint16 {
	return uint16(len(b.b.b.buf) - b.optStartOffset - 4)
}

// End finalizes the building process and reflects the changes made using the [EDNS0OptionBuilder] in the [ResourceOPTBuilder].
// This method must be called after writing the entire resource data is done.
// Attempting to use the EDNS0OptionBuilder after calling End might lead to panics.
func (b *EDNS0OptionBuilder) End() {
	packUint16(b.b.b.buf[b.optStartOffset+2:], b.Length())
	b.b.fakeLength = 0
	b.b = nil
}

// Remove removes the resource from the message.
// Attempting to use the ResourceOPTBuilder after calling Remove might lead to panics.
func (b *EDNS0OptionBuilder) Remove() {
	b.b.b.nb.removeNamesFromCompressionMap(b.b.b.headerStartOffset, b.optStartOffset)
	b.b.b.buf = b.b.b.buf[:b.optStartOffset]
	b.b.fakeLength = 0
	b.b = nil
}

// Name appends a DNS name to the option.
func (b *EDNS0OptionBuilder) Name(name Name, compress bool) error {
	nameOffset := len(b.b.b.buf)
	var err error
	b.b.b.buf, err = b.b.b.nb.appendName(b.b.b.buf, b.b.b.maxBufSize, b.b.b.headerStartOffset, name.asSlice(), compress)
	if err != nil {
		return err
	}

	if b.b.fixup.rDataLength(b.b.b) > math.MaxUint16 {
		b.b.b.nb.removeNamesFromCompressionMap(b.b.b.headerStartOffset, nameOffset)
		b.b.b.buf = b.b.b.buf[:nameOffset]
		return errResourceTooLong
	}
	return nil
}

// Bytes appends a raw byte slice to the option.
func (b *EDNS0OptionBuilder) Bytes(raw []byte) error {
	if b.b.fixup.rDataLength(b.b.b)+len(raw) > math.MaxUint16 {
		return errResourceTooLong
	}
	if len(b.b.b.buf)+len(raw) > b.b.b.maxBufSize {
		return ErrTruncated
	}
	b.b.b.buf = append(b.b.b.buf, raw...)
	return nil
}

// Uint8 appends a single uint8 value to the option.
func (b *EDNS0OptionBuilder) Uint8(val uint8) error {
	if b.b.fixup.rDataLength(b.b.b)+1 > math.MaxUint16 {
		return errResourceTooLong
	}
	if len(b.b.b.buf)+1 > b.b.b.maxBufSize {
		return ErrTruncated
	}
	b.b.b.buf = append(b.b.b.buf, val)
	return nil
}

// Uint16 appends a single uint16 value to the option in Big-Endian format.
func (b *EDNS0OptionBuilder) Uint16(val uint16) error {
	if b.b.fixup.rDataLength(b.b.b)+1 > math.MaxUint16 {
		return errResourceTooLong
	}
	if len(b.b.b.buf)+1 > b.b.b.maxBufSize {
		return ErrTruncated
	}
	b.b.b.buf = appendUint16(b.b.b.buf, val)
	return nil
}

// Uint32 appends a single uint32 value to the option in Big-Endian format.
func (b *EDNS0OptionBuilder) Uint32(val uint32) error {
	if b.b.fixup.rDataLength(b.b.b)+1 > math.MaxUint16 {
		return errResourceTooLong
	}
	if len(b.b.b.buf)+1 > b.b.b.maxBufSize {
		return ErrTruncated
	}
	b.b.b.buf = appendUint32(b.b.b.buf, val)
	return nil
}

// Uint64 appends a single uint64 value to the option in Big-Endian format.
func (b *EDNS0OptionBuilder) Uint64(val uint64) error {
	if b.b.fixup.rDataLength(b.b.b)+1 > math.MaxUint16 {
		return errResourceTooLong
	}
	if len(b.b.b.buf)+1 > b.b.b.maxBufSize {
		return ErrTruncated
	}
	b.b.b.buf = appendUint64(b.b.b.buf, val)
	return nil
}

// ResourceOPT parses a single OPT resource.
//
// Only known (supported by this package) options are parsed, unsupported options
// are skipped.
//
// This method can only be used after [Parser.ResourceHeader]
// returns a [ResourceHeader] with a Type field equal to [TypeOPT].
func (p *Parser) ResourceOPT() (ResourceOPT, error) {
	off := p.curOffset
	optp, err := p.ResourceOPTParser()
	if err != nil {
		return ResourceOPT{}, err
	}
	off, p.curOffset = p.curOffset, off

	var res ResourceOPT
	for {
		code, err := optp.Code()
		if err != nil {
			if err == ErrSectionDone {
				break
			}
			return ResourceOPT{}, err
		}

		switch code {
		case EDNS0OptionCodeClientSubnet:
			opt, err := optp.ClientSubnet()
			if err != nil {
				return ResourceOPT{}, err
			}
			res.Options = append(res.Options, &opt)
		case EDNS0OptionCodeCookie:
			opt, err := optp.Cookie()
			if err != nil {
				return ResourceOPT{}, err
			}
			res.Options = append(res.Options, &opt)
		case EDNS0OptionCodeExtendedDNSError:
			opt, err := optp.ExtendedDNSError()
			if err != nil {
				return ResourceOPT{}, err
			}
			res.Options = append(res.Options, &opt)
		default:
			if err := optp.Skip(); err != nil {
				return ResourceOPT{}, err
			}
		}
	}

	p.curOffset = off
	return res, nil
}

// ResourceOPTParser creates a single [ResourceOPTParser].
//
// This method can only be used after [Parser.ResourceHeader]
// returns a [ResourceHeader] with a Type field equal to [TypeOPT].
func (m *Parser) ResourceOPTParser() (ResourceOPTParser, error) {
	if !m.resourceData || m.nextResourceType != TypeOPT {
		return ResourceOPTParser{}, errInvalidOperation
	}

	if len(m.msg)-m.curOffset < int(m.nextResourceDataLength) {
		return ResourceOPTParser{}, errInvalidDNSMessage
	}

	m.resourceData = false
	offset := m.curOffset
	m.curOffset += int(m.nextResourceDataLength)
	return ResourceOPTParser{
		p:         m,
		offset:    offset,
		maxOffset: m.curOffset,
	}, nil
}

// ResourceOPTParser is an incremental parser of an OPT resource.
type ResourceOPTParser struct {
	p         *Parser
	offset    int
	maxOffset int
	nextData  bool
	nextCode  EDNS0OptionCode
}

// Code parses the header of a OPT option and returns a [EDNS0OptionCode].
func (p *ResourceOPTParser) Code() (EDNS0OptionCode, error) {
	if p.nextData {
		return 0, errInvalidOperation
	}
	if p.offset == p.maxOffset {
		return 0, ErrSectionDone
	}
	if p.maxOffset-p.offset < 4 {
		return 0, errInvalidDNSMessage
	}
	p.nextCode = EDNS0OptionCode(unpackUint16(p.p.msg[p.offset:]))
	p.offset += 2
	p.nextData = true
	return p.nextCode, nil
}

// Skip skips the option data.
func (p *ResourceOPTParser) Skip() error {
	if !p.nextData {
		return errInvalidOperation
	}
	length := unpackUint16(p.p.msg[p.offset:])
	if p.maxOffset-p.offset < int(length) {
		return errInvalidDNSMessage
	}
	p.offset += int(length) + 2
	p.nextData = false
	return nil
}

// ClientSubnet parses a single [EDNS0ClientSubnet] option.
//
// Note: This function should only be called when the [ResourceOPTParser.Code]
// method returns a [EDNS0OptionCodeClientSubnet] code.
func (p *ResourceOPTParser) ClientSubnet() (EDNS0ClientSubnet, error) {
	if !p.nextData || p.nextCode != EDNS0OptionCodeClientSubnet {
		return EDNS0ClientSubnet{}, errInvalidOperation
	}

	length := unpackUint16(p.p.msg[p.offset:])
	if length < 3 {
		return EDNS0ClientSubnet{}, errInvalidDNSMessage
	}
	if p.maxOffset-p.offset-2 < int(length) {
		return EDNS0ClientSubnet{}, errInvalidDNSMessage
	}
	raw := p.p.msg[p.offset+2 : p.offset+int(length)+2]

	p.offset += int(length) + 2
	p.nextData = false
	return EDNS0ClientSubnet{
		Family:             AddressFamily(raw[0]),
		SourcePrefixLength: raw[1],
		ScopePrefixLength:  raw[2],
		Address:            raw[3:],
	}, nil
}

// Cookie parses a single [EDNS0Cookie] option.
//
// Note: This function should only be called when the [ResourceOPTParser.Code]
// method returns a [EDNS0OptionCodeCookie] code.
func (p *ResourceOPTParser) Cookie() (EDNS0Cookie, error) {
	if !p.nextData || p.nextCode != EDNS0OptionCodeCookie {
		return EDNS0Cookie{}, errInvalidOperation
	}

	length := unpackUint16(p.p.msg[p.offset:])
	if p.maxOffset-p.offset-2 < int(length) {
		return EDNS0Cookie{}, errInvalidDNSMessage
	}
	raw := p.p.msg[p.offset+2 : p.offset+int(length)+2]
	if len(raw) < 8 || len(raw) > 40 || (len(raw) > 8 && len(raw) < 16) {
		return EDNS0Cookie{}, errInvalidDNSMessage
	}

	var serverCookie [32]byte
	n := copy(serverCookie[:], raw[8:])

	p.offset += int(length) + 2
	p.nextData = false
	return EDNS0Cookie{
		ClientCookie:                 [8]byte(raw),
		ServerCookie:                 serverCookie,
		ServerCookieAdditionalLength: uint8(n) - 8,
	}, nil
}

// ExtendedDNSError parses a single [EDNS0ExtendedDNSError] option.
//
// Note: This function should only be called when the [ResourceOPTParser.Code]
// method returns a [EDNS0OptionCodeExtendedDNSError] code.
func (p *ResourceOPTParser) ExtendedDNSError() (EDNS0ExtendedDNSError, error) {
	if !p.nextData || p.nextCode != EDNS0OptionCodeExtendedDNSError {
		return EDNS0ExtendedDNSError{}, errInvalidOperation
	}

	length := unpackUint16(p.p.msg[p.offset:])
	if length < 2 {
		return EDNS0ExtendedDNSError{}, errInvalidDNSMessage
	}
	if p.maxOffset-p.offset-2 < int(length) {
		return EDNS0ExtendedDNSError{}, errInvalidDNSMessage
	}
	raw := p.p.msg[p.offset+2 : p.offset+int(length)+2]

	p.nextData = false
	p.offset += int(length) + 2
	return EDNS0ExtendedDNSError{
		InfoCode: ExtendedDNSErrorCode(unpackUint16(raw)),
		// TODO: UTF8-8 validate?
		ExtraText: raw[2:],
	}, nil
}

// OptionParser creates a single [EDNS0OptionParser] which can be used for parsing custom options.
func (p *ResourceOPTParser) OptionParser() (EDNS0OptionParser, error) {
	if !p.nextData {
		return EDNS0OptionParser{}, errInvalidOperation
	}
	offset := p.offset
	p.offset += 2 + int(unpackUint16(p.p.msg[offset:]))
	if p.offset > p.maxOffset {
		p.offset = offset
		return EDNS0OptionParser{}, errInvalidDNSMessage
	}
	return EDNS0OptionParser{
		rd: RDParser{
			m:         p.p,
			offset:    offset + 2,
			maxOffset: p.offset,
		},
	}, nil
}

// EDNS0OptionParser is a option parser used to parse custom OPT options.
type EDNS0OptionParser struct {
	rd RDParser
}

// Length returns the remaining bytes in the option data.
func (p *EDNS0OptionParser) Length() uint16 {
	return p.rd.Length()
}

// End checks if there is any remaining data in the option data being parsed.
// It is used to ensure that the entire option data has been successfully parsed and
// no unexpected data remains.
func (p *EDNS0OptionParser) End() error {
	return p.rd.End()
}

// Name parses a single DNS name.
func (p *EDNS0OptionParser) Name() (Name, error) {
	return p.rd.Name()
}

// AllBytes returns all remaining bytes in p.
// The length of the byte slice is equal to [EDNS0OptionParser.Length].
//
// The returned slice references the underlying message pased to [Parse].
func (p *EDNS0OptionParser) AllBytes() []byte {
	return p.rd.AllBytes()
}

// Bytes returns a n-length slice, errors when [EDNS0OptionParser.Length} < n.
//
// The returned slice references the underlying message pased to [Parse].
func (p *EDNS0OptionParser) Bytes(n int) ([]byte, error) {
	return p.rd.Bytes(n)
}

// Uint8 parses a single uint8 value.
// It requires at least one byte to be available in the EDNS0OptionParser to successfully parse.
func (p *EDNS0OptionParser) Uint8() (uint8, error) {
	return p.rd.Uint8()
}

// Uint16 parses a single Big-Endian uint16 value.
// It requires at least two bytes to be available in the EDNS0OptionParser to successfully parse.
func (p *EDNS0OptionParser) Uint16() (uint16, error) {
	return p.rd.Uint16()
}

// Uint32 parses a single Big-Endian uint32 value.
// It requires at least four bytes to be available in the EDNS0OptionParser to successfully parse.
func (p *EDNS0OptionParser) Uint32() (uint32, error) {
	return p.rd.Uint32()
}

// Uint64 parses a single Big-Endian uint64 value.
// It requires at least eight bytes to be available in the EDNS0OptionParser to successfully parse.
func (p *EDNS0OptionParser) Uint64() (uint64, error) {
	return p.rd.Uint64()
}
