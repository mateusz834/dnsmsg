package dnsmsg

import (
	"bytes"
	"errors"
	"hash/maphash"
	"math"
)

var (
	// ErrTruncated is an error returned by [Builder] when appending questions or resources to the message
	// is not possible due to reaching the maximum size limit set by [Builder.LimitMessageSize].
	// When this error occurs, it indicates that the total size of the DNS message, has reached or exceeded
	// the specified size limit.
	//
	// The DNS message, upon encountering the ErrTruncated error, remains valid, and shorter resources can still be appended
	// to the message. The error serves as a notification that the message has reached its size limit and indicates that the
	// application may need to handle this condition appropriately. Two common approaches to handle this situation
	// include setting the TC (Truncated) bit or sending fewer resources (RFC 2181, Section 9).
	ErrTruncated = errors.New("message size limit reached")
)

type section uint8

const (
	sectionQuestions section = iota
	sectionAnswers
	sectionAuthorities
	sectionAdditionals

	sectionDetachedMask section = 1 << 7
)

// Builder is an incremental DNS message builder.
//
// Internally the Builder contains a building section field, that can be changed
// using one of these methods: [Builder.StartAnswers], [Builder.StartAuthorities], [Builder.StartAdditionals].
// By default the building section is set to questions, it allows appending questions by the
// use of the [Builder.Question] method.
// After changing the building section (using one of the Start* methods described above) the
// resource building methods: [Builder.ResourceA], [Builder.ResourceAAAA], [Builder.ResourceNS], [Builder.ResourceCNAME],
// [Builder.ResourceSOA], [Builder.ResourcePTR], [Builder.ResourceMX], [Builder.RawResourceTXT], [Builder.ResourceTXT]
// or [Builder.RDBuilder] can be used to append DNS resources.
//
// The zero value of this type shouldn't be used.
type Builder struct {
	_ noCopy

	buf []byte
	nb  nameBuilderState

	fakeBufSize       int
	headerStartOffset int
	maxBufSize        int

	curSection section
	hdr        Header
}

// StartBuilder creates a new DNS builder.
// The message is going to be appended to the provided byte slice (buf).
func StartBuilder(buf []byte, id uint16, flags Flags) Builder {
	return Builder{
		headerStartOffset: len(buf),
		buf:               append(buf, make([]byte, headerLen)...),
		fakeBufSize:       math.MaxInt,
		maxBufSize:        math.MaxInt,
		hdr: Header{
			ID:    id,
			Flags: flags,
		},
	}
}

func (b *Builder) panicInvalidSection() {
	if b.curSection&sectionDetachedMask != 0 {
		panic("dnsmsg: invalid usage of the Builder: the Builder is currently detached to a resource data builder, call End() or Remove() before on the resource data builder")
	}
	panic("invalid section")
}

// LimitMessageSize sets the upper limit on the size of the DNS message that can be built using the Builder.
// It allows you to restrict the message size to a specified value, preventing it from exceeding the threshold.
// If the total size of the message reaches or exceeds the given size, any subsequent appending
// of questions or resources will result in an error [ErrTruncated]. Despite encountering the [ErrTruncated] error,
// the DNS message remains valid, and shorter resources can still be appended.
//
// Note: The message size will not be reduced if it is already larger than the specified limit.
func (b *Builder) LimitMessageSize(size int) {
	b.maxBufSize = b.headerStartOffset + size
}

// Reset restes the DNS builder.
// The message is going to be appended to the provided byte slice (buf).
func (b *Builder) Reset(buf []byte, id uint16, flags Flags) {
	nb := b.nb
	nb.reset()
	*b = StartBuilder(buf, id, flags)
	b.nb = nb
}

// Bytes returns the built DNS message.
//
// Note: Calling this method multiple times may result in invalid results, as it only returns the
// current state of the DNS message. Any previous calls to Bytes() should be considered invalid.
func (b *Builder) Bytes() []byte {
	b.hdr.pack((*[12]byte)(b.buf[b.headerStartOffset:]))
	bufSize := b.fakeBufSize
	if bufSize > len(b.buf) {
		bufSize = len(b.buf)
	}
	return b.buf[:bufSize]
}

// Length returns the number of bytes that have been appended to the DNS message up to this point.
func (b *Builder) Length() int {
	bufSize := b.fakeBufSize
	if bufSize > len(b.buf) {
		bufSize = len(b.buf)
	}
	return bufSize - b.headerStartOffset
}

// Header returns the current state of the builder's header.
func (b *Builder) Header() Header {
	return b.hdr
}

// SetID updates the id in the header.
func (b *Builder) SetID(id uint16) {
	b.hdr.ID = id
}

// SetFlags updates the flags in the header.
func (b *Builder) SetFlags(flags Flags) {
	b.hdr.Flags = flags
}

// StartAnswers changes the building section from question to answers.
//
// It Panics when the current building section is not questions.
func (b *Builder) StartAnswers() {
	if b.curSection != sectionQuestions {
		b.panicInvalidSection()
	}
	b.curSection = sectionAnswers
}

// StartAuthorities changes the building section from answers to authorities.
//
// It Panics when the current building section is not answers.
func (b *Builder) StartAuthorities() {
	if b.curSection != sectionAnswers {
		b.panicInvalidSection()
	}
	b.curSection = sectionAuthorities
}

// StartAuthorities changes the building section from authorities to additionals.
//
// It Panics when the current building section is not additionals.
func (b *Builder) StartAdditionals() {
	if b.curSection != sectionAuthorities {
		b.panicInvalidSection()
	}
	b.curSection = sectionAdditionals
}

var errResourceCountLimitReached = errors.New("maximum amount of DNS resources/questions reached")

func (b *Builder) incResurceSection() error {
	var count *uint16
	switch b.curSection {
	case sectionAnswers:
		count = &b.hdr.ANCount
	case sectionAuthorities:
		count = &b.hdr.NSCount
	case sectionAdditionals:
		count = &b.hdr.ARCount
	default:
		b.panicInvalidSection()
	}

	if *count == math.MaxUint16 {
		return errResourceCountLimitReached
	}
	*count++
	return nil
}

func (b *Builder) decResurceSection() {
	switch b.curSection {
	case sectionAnswers:
		b.hdr.ANCount--
	case sectionAuthorities:
		b.hdr.NSCount--
	case sectionAdditionals:
		b.hdr.ARCount--
	}
}

// Question appends a single question.
// It errors when the amount of questions is equal to 65535.
//
// The building section must be set to questions, otherwise it panics.
func (b *Builder) Question(q Question) error {
	if b.curSection != sectionQuestions {
		b.panicInvalidSection()
	}

	if b.hdr.QDCount == math.MaxUint16 {
		return errResourceCountLimitReached
	}

	var err error
	b.buf, err = b.nb.appendName(b.buf, b.maxBufSize-4, b.headerStartOffset, q.Name.asSlice(), true)
	if err != nil {
		return err
	}
	b.buf = appendUint16(b.buf, uint16(q.Type))
	b.buf = appendUint16(b.buf, uint16(q.Class))

	b.hdr.QDCount++
	return nil
}

// ResourceA appends a single A resource.
// It errors when the amount of resources in the current section is equal to 65535.
//
// The building section must NOT be set to questions, otherwise it panics.
func (b *Builder) ResourceA(hdr ResourceHeader, a ResourceA) error {
	hdr.Type = TypeA
	hdr.Length = 4
	if err := b.appendHeader(hdr, b.maxBufSize-4); err != nil {
		return err
	}
	b.buf = append(b.buf, a.A[:]...)
	return nil
}

// ResourceAAAA appends a single AAAA resource.
// It errors when the amount of resources in the current section is equal to 65535.
//
// The building section must NOT be set to questions, otherwise it panics.
func (b *Builder) ResourceAAAA(hdr ResourceHeader, aaaa ResourceAAAA) error {
	hdr.Type = TypeAAAA
	hdr.Length = 16
	if err := b.appendHeader(hdr, b.maxBufSize-16); err != nil {
		return err
	}
	b.buf = append(b.buf, aaaa.AAAA[:]...)
	return nil
}

// ResourceNS appends a single NS resource.
// It errors when the amount of resources in the current section is equal to 65535.
//
// The building section must NOT be set to questions, otherwise it panics.
func (b *Builder) ResourceNS(hdr ResourceHeader, ns ResourceNS) error {
	hdr.Type = TypeNS
	f, hdrOffset, err := b.appendHeaderWithLengthFixup(hdr, b.maxBufSize)
	if err != nil {
		return err
	}
	b.buf, err = b.nb.appendName(b.buf, b.maxBufSize, b.headerStartOffset, ns.NS.asSlice(), true)
	if err != nil {
		b.removeResourceHeader(hdrOffset)
		return err
	}
	f.fixup(b)
	return nil
}

// ResourceCNAME appends a single CNAME resource.
// It errors when the amount of resources in the current section is equal to 65535.
//
// The building section must NOT be set to questions, otherwise it panics.
func (b *Builder) ResourceCNAME(hdr ResourceHeader, cname ResourceCNAME) error {
	hdr.Type = TypeCNAME
	f, hdrOffset, err := b.appendHeaderWithLengthFixup(hdr, b.maxBufSize)
	if err != nil {
		return err
	}
	b.buf, err = b.nb.appendName(b.buf, b.maxBufSize, b.headerStartOffset, cname.CNAME.asSlice(), true)
	if err != nil {
		b.removeResourceHeader(hdrOffset)
		return err
	}
	f.fixup(b)
	return nil
}

// ResourceSOA appends a single SOA resource.
// It errors when the amount of resources in the current section is equal to 65535.
//
// The building section must NOT be set to questions, otherwise it panics.
func (b *Builder) ResourceSOA(hdr ResourceHeader, soa ResourceSOA) error {
	hdr.Type = TypeSOA
	f, hdrOffset, err := b.appendHeaderWithLengthFixup(hdr, b.maxBufSize)
	if err != nil {
		return err
	}

	b.buf, err = b.nb.appendName(b.buf, b.maxBufSize, b.headerStartOffset, soa.NS.asSlice(), true)
	if err != nil {
		b.removeResourceHeader(hdrOffset)
		return err
	}

	b.buf, err = b.nb.appendName(b.buf, b.maxBufSize-20, b.headerStartOffset, soa.Mbox.asSlice(), true)
	if err != nil {
		b.removeResourceHeader(hdrOffset)
		return err
	}

	b.buf = appendUint32(b.buf, soa.Serial)
	b.buf = appendUint32(b.buf, soa.Refresh)
	b.buf = appendUint32(b.buf, soa.Retry)
	b.buf = appendUint32(b.buf, soa.Expire)
	b.buf = appendUint32(b.buf, soa.Minimum)
	f.fixup(b)
	return nil
}

// ResourcePTR appends a single PTR resource.
// It errors when the amount of resources in the current section is equal to 65535.
//
// The building section must NOT be set to questions, otherwise it panics.
func (b *Builder) ResourcePTR(hdr ResourceHeader, ptr ResourcePTR) error {
	hdr.Type = TypePTR
	f, hdrOffset, err := b.appendHeaderWithLengthFixup(hdr, b.maxBufSize)
	if err != nil {
		return err
	}
	b.buf, err = b.nb.appendName(b.buf, b.maxBufSize, b.headerStartOffset, ptr.PTR.asSlice(), true)
	if err != nil {
		b.removeResourceHeader(hdrOffset)
		return err
	}
	f.fixup(b)
	return nil
}

// ResourceMX appends a single MX resource.
// It errors when the amount of resources in the current section is equal to 65535.
//
// The building section must NOT be set to questions, otherwise it panics.
func (b *Builder) ResourceMX(hdr ResourceHeader, mx ResourceMX) error {
	hdr.Type = TypeMX
	f, hdrOffset, err := b.appendHeaderWithLengthFixup(hdr, b.maxBufSize-2)
	if err != nil {
		return err
	}
	b.buf = appendUint16(b.buf, mx.Pref)
	b.buf, err = b.nb.appendName(b.buf, b.maxBufSize, b.headerStartOffset, mx.MX.asSlice(), true)
	if err != nil {
		b.removeResourceHeader(hdrOffset)
		return err
	}
	f.fixup(b)
	return nil
}

var errInvalidRawTXTResource = errors.New("invalid raw txt resource")

// RawResourceTXT appends a single TXT resource.
// It errors when the amount of resources in the current section is equal to 65535.
//
// The building section must NOT be set to questions, otherwise it panics.
func (b *Builder) RawResourceTXT(hdr ResourceHeader, txt RawResourceTXT) error {
	hdr.Type = TypeTXT
	if len(txt.TXT) > math.MaxUint16 || !txt.isValid() {
		return errInvalidRawTXTResource
	}

	hdr.Length = uint16(len(txt.TXT))
	if err := b.appendHeader(hdr, b.maxBufSize-len(txt.TXT)); err != nil {
		return err
	}
	b.buf = append(b.buf, txt.TXT...)
	return nil
}

var errEmptyTXT = errors.New("empty txt resource")
var errTooLongTXTString = errors.New("too long txt string")
var errTooLongTXT = errors.New("too long txt resource")

// ResourceTXT appends a single TXT resource.
// It errors when the amount of resources in the current section is equal to 65535.
//
// The building section must NOT be set to questions, otherwise it panics.
func (b *Builder) ResourceTXT(hdr ResourceHeader, txt ResourceTXT) error {
	hdr.Type = TypeTXT
	totalLength := 0
	for _, str := range txt.TXT {
		if len(str) > math.MaxUint8 {
			return errTooLongTXTString
		}
		totalLength += 1 + len(str)
		if totalLength > math.MaxUint16 {
			return errTooLongTXT
		}
	}

	if totalLength == 0 {
		return errEmptyTXT
	}

	hdr.Length = uint16(totalLength)
	if err := b.appendHeader(hdr, b.maxBufSize-totalLength); err != nil {
		return err
	}

	for _, str := range txt.TXT {
		b.buf = append(b.buf, uint8(len(str)))
		b.buf = append(b.buf, str...)
	}

	return nil
}

func (b *Builder) appendHeader(hdr ResourceHeader, maxBufSize int) error {
	if err := b.incResurceSection(); err != nil {
		return err
	}
	var err error
	b.buf, err = b.nb.appendName(b.buf, maxBufSize-10, b.headerStartOffset, hdr.Name.asSlice(), true)
	if err != nil {
		b.decResurceSection()
		return err
	}
	b.buf = appendUint16(b.buf, uint16(hdr.Type))
	b.buf = appendUint16(b.buf, uint16(hdr.Class))
	b.buf = appendUint32(b.buf, hdr.TTL)
	b.buf = appendUint16(b.buf, hdr.Length)
	return nil
}

type headerLengthFixup int

func (f headerLengthFixup) rDataLength(b *Builder) int {
	return len(b.buf) - int(f)
}

func (f headerLengthFixup) fixup(b *Builder) {
	packUint16(b.buf[f-2:], uint16(f.rDataLength(b)))
}

func (f headerLengthFixup) currentlyStoredLength(b *Builder) uint16 {
	return unpackUint16(b.buf[f-2:])
}

func (b *Builder) appendHeaderWithLengthFixup(hdr ResourceHeader, maxBufSize int) (headerLengthFixup, int, error) {
	err := b.incResurceSection()
	if err != nil {
		return 0, 0, err
	}
	nameOffset := len(b.buf)
	b.buf, err = b.nb.appendName(b.buf, maxBufSize-10, b.headerStartOffset, hdr.Name.asSlice(), true)
	if err != nil {
		b.decResurceSection()
		return 0, 0, err
	}
	b.buf = appendUint16(b.buf, uint16(hdr.Type))
	b.buf = appendUint16(b.buf, uint16(hdr.Class))
	b.buf = appendUint32(b.buf, hdr.TTL)
	b.buf = appendUint16(b.buf, hdr.Length)
	return headerLengthFixup(len(b.buf)), nameOffset, nil
}

func (b *Builder) appendHeaderWithLengthFixupNoInc(hdr ResourceHeader, maxBufSize int) (headerLengthFixup, int, *uint16, error) {
	var count *uint16
	switch b.curSection {
	case sectionAnswers:
		count = &b.hdr.ANCount
	case sectionAuthorities:
		count = &b.hdr.NSCount
	case sectionAdditionals:
		count = &b.hdr.ARCount
	default:
		b.panicInvalidSection()
	}

	if *count == math.MaxUint16 {
		return 0, 0, nil, errResourceCountLimitReached
	}

	var err error
	nameOffset := len(b.buf)
	b.buf, err = b.nb.appendName(b.buf, maxBufSize-10, b.headerStartOffset, hdr.Name.asSlice(), true)
	if err != nil {
		return 0, 0, nil, err
	}
	b.buf = appendUint16(b.buf, uint16(hdr.Type))
	b.buf = appendUint16(b.buf, uint16(hdr.Class))
	b.buf = appendUint32(b.buf, hdr.TTL)
	b.buf = appendUint16(b.buf, 0)
	return headerLengthFixup(len(b.buf)), nameOffset, count, nil
}

func (b *Builder) removeResourceHeader(headerOffset int) {
	b.nb.removeNamesFromCompressionMap(b.headerStartOffset, headerOffset)
	b.buf = b.buf[:headerOffset]
	b.decResurceSection()
}

// RDBuilder craeates a new [RDBuilder], used for building custom resource data.
// It errors when the amount of resources in the current section is equal to 65535.
//
// Note: The returned RDBuilder should not be used after creating any new resource in b.
// Once a resource is created using the RDBuilder, attempting to use the same RDBuilder again might lead to panics.
//
// The building section must NOT be set to questions, otherwise it panics.
func (b *Builder) RDBuilder(hdr ResourceHeader) (RDBuilder, error) {
	f, hdrOffset, count, err := b.appendHeaderWithLengthFixupNoInc(hdr, b.maxBufSize)
	if err != nil {
		return RDBuilder{}, err
	}
	b.fakeBufSize = hdrOffset
	b.curSection |= sectionDetachedMask
	return RDBuilder{
		b:         b,
		count:     count,
		fixup:     f,
		hdrOffset: hdrOffset,
	}, nil
}

// RDParser is a resource data builder used to build custom resources.
//
// Once the entire resource data has been created, the [RDBuilder.End] method needs to be called.
//
// Note: The returned RDBuilder should not be used after creating any new resource in the [Builder].
// Once a resource is created using the RDBuilder, attempting to use the same RDBuilder might lead to panics.
type RDBuilder struct {
	_ noCopy

	b         *Builder
	count     *uint16
	fixup     headerLengthFixup
	hdrOffset int
}

var errResourceTooLong = errors.New("too long resource")

// Length returns the current length of the resource data in bytes.
func (b *RDBuilder) Length() uint16 {
	return uint16(b.length())
}

func (b *RDBuilder) length() int {
	return b.fixup.rDataLength(b.b)
}

// End finalizes the resource data building process and reflects the changes made using the RDBuilder in the Builder.
// This method must be called after writing the entire resource data is done.
// Attempting to use the RDBuilder after calling End might lead to panics.
func (b *RDBuilder) End() {
	b.b.fakeBufSize = math.MaxInt
	b.b.curSection &= ^sectionDetachedMask
	b.fixup.fixup(b.b)
	*b.count++
	b.b = nil
}

// Remove removes the resource from the message.
// Attempting to use the RDBuilder after calling Remove might lead to panics.
func (b *RDBuilder) Remove() {
	b.b.fakeBufSize = math.MaxInt
	b.b.curSection &= ^sectionDetachedMask
	b.b.nb.removeNamesFromCompressionMap(b.b.headerStartOffset, b.hdrOffset)
	b.b.buf = b.b.buf[:b.hdrOffset]
	b.b = nil
}

// Name appends a DNS name to the resource data.
//
// If the resource data exceeds the maximum allowed size of 64 KiB or the message limit size
// is reached ([Builder.LimitMessageSize]), an error will be returned.
// Note: In case of an error, the resource is not removed, and you can still use the RDBuilder safely.
// The Resource can be removed via the [RDBuilder.Remove] method.
func (b *RDBuilder) Name(name Name, compress bool) error {
	nameOffset := len(b.b.buf)
	var err error
	b.b.buf, err = b.b.nb.appendName(b.b.buf, b.b.maxBufSize, b.b.headerStartOffset, name.asSlice(), compress)
	if err != nil {
		return err
	}

	if b.fixup.rDataLength(b.b) > math.MaxUint16 {
		b.b.nb.removeNamesFromCompressionMap(b.b.headerStartOffset, nameOffset)
		b.b.buf = b.b.buf[:nameOffset]
		return errResourceTooLong
	}
	return nil
}

// Bytes appends a raw byte slice to the resource data.
//
// If the resource data exceeds the maximum allowed size of 64 KiB or the message limit size
// is reached ([Builder.LimitMessageSize]), an error will be returned.
// Note: In case of an error, the resource is not removed, and you can still use the RDBuilder safely.
// The Resource can be removed via the [RDBuilder.Remove] method.
func (b *RDBuilder) Bytes(raw []byte) error {
	if b.length()+len(raw) > math.MaxUint16 {
		return errResourceTooLong
	}
	if len(b.b.buf)+len(raw) > b.b.maxBufSize {
		return ErrTruncated
	}
	b.b.buf = append(b.b.buf, raw...)
	return nil
}

// Uint8 appends a single uint8 value to the resource data.
//
// If the resource data exceeds the maximum allowed size of 64 KiB or the message limit size
// is reached ([Builder.LimitMessageSize]), an error will be returned.
// Note: In case of an error, the resource is not removed, and you can still use the RDBuilder safely.
// The Resource can be removed via the [RDBuilder.Remove] method.
func (b *RDBuilder) Uint8(val uint8) error {
	if b.length()+1 > math.MaxUint16 {
		return errResourceTooLong
	}
	if len(b.b.buf)+1 > b.b.maxBufSize {
		return ErrTruncated
	}
	b.b.buf = append(b.b.buf, val)
	return nil
}

// Uint16 appends a single uint16 value to the resource data in Big-Endian format.
//
// If the resource data exceeds the maximum allowed size of 64 KiB or the message limit size
// is reached ([Builder.LimitMessageSize]), an error will be returned.
// Note: In case of an error, the resource is not removed, and you can still use the RDBuilder safely.
// The Resource can be removed via the [RDBuilder.Remove] method.
func (b *RDBuilder) Uint16(val uint16) error {
	if b.length()+2 > math.MaxUint16 {
		return errResourceTooLong
	}
	if len(b.b.buf)+2 > b.b.maxBufSize {
		return ErrTruncated
	}
	b.b.buf = appendUint16(b.b.buf, val)
	return nil
}

// Uint32 appends a single uint16 value to the resource data in Big-Endian format.
//
// If the resource data exceeds the maximum allowed size of 64 KiB or the message limit size
// is reached ([Builder.LimitMessageSize]), an error will be returned.
// Note: In case of an error, the resource is not removed, and you can still use the RDBuilder safely.
// The Resource can be removed via the [RDBuilder.Remove] method.
func (b *RDBuilder) Uint32(val uint32) error {
	if b.length()+4 > math.MaxUint16 {
		return errResourceTooLong
	}
	if len(b.b.buf)+4 > b.b.maxBufSize {
		return ErrTruncated
	}
	b.b.buf = appendUint32(b.b.buf, val)
	return nil
}

// Uint64 appends a single uint16 value to the resource data in Big-Endian format.
//
// If the resource data exceeds the maximum allowed size of 64 KiB or the message limit size
// is reached ([Builder.LimitMessageSize]), an error will be returned.
// Note: In case of an error, the resource is not removed, and you can still use the RDBuilder safely.
// The Resource can be removed via the [RDBuilder.Remove] method.
func (b *RDBuilder) Uint64(val uint64) error {
	if b.length()+8 > math.MaxUint16 {
		return errResourceTooLong
	}
	if len(b.b.buf)+8 > b.b.maxBufSize {
		return ErrTruncated
	}
	b.b.buf = appendUint64(b.b.buf, val)
	return nil
}

const (
	ptrBits = 14
	maxPtr  = (1 << ptrBits) - 1
)

type fingerprint uint32

func takeFingerprint(hash uint64) fingerprint {
	return fingerprint(hash >> (64 - (32 - ptrBits)))
}

// leading (32-ptrBits) bits are used as a fingerprint,
// trailing ptrBits represents a DNS compression pointer.
type entry uint32

func (m entry) isFree() bool {
	return m == 0
}

func (m entry) ptr() uint16 {
	return uint16(m) & maxPtr
}

func (m entry) fingerprint() fingerprint {
	return fingerprint(uint32(m) & ^uint32(maxPtr)) >> ptrBits
}

func (m *entry) fill(f fingerprint, ptr uint16) {
	*m = entry(uint32(f)<<ptrBits | uint32(ptr))
}

func (m *entry) clear() {
	*m = 0
}

type nameBuilderState struct {
	entries          []entry
	available        int
	seed             maphash.Seed
	invalidPtrsAfter uint16
	firstNameLength  uint8
}

func (c *nameBuilderState) reset() {
	for i := range c.entries {
		c.entries[i] = 0
	}
	c.available = len(c.entries)
	c.invalidPtrsAfter = 0
	c.firstNameLength = 0
}

func (m *nameBuilderState) appendName(msg []byte, msgSizeLimit, headerStartOffset int, name []byte, compress bool) ([]byte, error) {
	if m.firstNameLength == 0 {
		if len(msg)+len(name) > msgSizeLimit {
			return msg, ErrTruncated
		}
		m.firstNameLength = uint8(len(name))
		return append(msg, name...), nil
	}

	if len(name) == 1 {
		if len(msg)+1 > msgSizeLimit {
			return msg, ErrTruncated
		}
		return append(msg, 0), nil
	}

	firstName := msg[headerLen+headerStartOffset:][:m.firstNameLength]
	if compress && bytes.Equal(firstName, name) {
		if len(msg)+2 > msgSizeLimit {
			return msg, ErrTruncated
		}
		return appendUint16(msg, headerLen|0xC000), nil
	}

	if m.invalidPtrsAfter != 0 {
		for i := range m.entries {
			ent := &m.entries[i]
			if int(ent.ptr()) >= int(m.invalidPtrsAfter) {
				ent.clear()
				m.available++
			}
		}
		m.invalidPtrsAfter = 0
	}

	for i := 0; name[i] != 0; i += int(name[i]) + 1 {
		if len(msg)+i+2 > msgSizeLimit {
			if len(msg) <= maxPtr {
				m.invalidPtrsAfter = uint16(len(msg))
			}
			return msg, ErrTruncated
		}

		startOffset := len(firstName) - len(name[i:])
		if compress && startOffset >= 0 && bytes.Equal(firstName[startOffset:], name[i:]) {
			msg = append(msg, name[:i]...)
			return appendUint16(msg, 0xC000|(headerLen+uint16(startOffset))), nil
		}

		if m.available == 0 {
			m.grow(msg[headerStartOffset:], name)
		}

		var (
			hash        = maphash.Bytes(m.seed, name[i:])
			mask        = uint(len(m.entries) - 1)
			fingerprint = takeFingerprint(hash)
			idx         = uint(hash) & uint(mask)
		)

		for !m.entries[idx].isFree() {
			if !compress {
				idx = (idx + 1) & mask
				continue
			}

			m := m.entries[idx]
			if m.fingerprint() == fingerprint {
				msgNameIndex := int(m.ptr()) + headerStartOffset
				if msgNameIndex < len(msg) {
					rawNameIndex := i
					for {
						if msg[msgNameIndex]&0xC0 == 0xC0 {
							msgNameIndex = int(msg[msgNameIndex]^0xC0)<<8 | int(msg[msgNameIndex+1])
						}

						labelLength := int(msg[msgNameIndex])

						if labelLength != int(name[rawNameIndex]) {
							break
						}

						if labelLength == 0 {
							msg = append(msg, name[:i]...)
							return appendUint16(msg, m.ptr()|0xC000), nil
						}

						msgNameIndex++
						rawNameIndex++

						if !bytes.Equal(msg[msgNameIndex:msgNameIndex+labelLength], name[rawNameIndex:rawNameIndex+labelLength]) {
							break
						}

						msgNameIndex += labelLength
						rawNameIndex += labelLength
					}
				}
			}
			idx = (idx + 1) & mask
		}

		newPtr := len(msg) - headerStartOffset + i
		if newPtr <= maxPtr {
			m.available--
			m.entries[idx].fill(fingerprint, uint16(newPtr))
		}
	}

	if len(msg)+len(name) > msgSizeLimit {
		if len(msg) <= maxPtr {
			m.invalidPtrsAfter = uint16(len(msg))
		}
		return msg, ErrTruncated
	}
	return append(msg, name...), nil
}

func (m *nameBuilderState) removeNamesFromCompressionMap(headerStartOffset, namesStartOffset int) {
	namesStartOffset -= headerStartOffset
	if namesStartOffset <= maxPtr {
		m.invalidPtrsAfter = uint16(namesStartOffset)
		if namesStartOffset == headerLen {
			m.firstNameLength = 0
		}
	}
}

func (m *nameBuilderState) grow(msg, name []byte) {
	length := len(m.entries) * 2
	if length == 0 {
		length = 16
		m.seed = maphash.MakeSeed()
	}

	oldEntries := m.entries
	m.entries = make([]entry, length)
	m.available = length

	var h maphash.Hash
	for _, entry := range oldEntries {
		if entry.isFree() {
			continue
		}

		var (
			offset = int(entry.ptr())
			hash   = uint64(0)
		)

		if offset >= len(msg) {
			// Hash map is growing, but the current name hasn't been inserted to the message yet.
			hash = maphash.Bytes(m.seed, name[offset-len(msg):])
		} else {
			h.SetSeed(m.seed)
			for {
				if msg[offset]&0xC0 == 0xC0 {
					offset = int(msg[offset]^0xC0)<<8 | int(msg[offset+1])
				}

				labelLength := int(msg[offset])
				if labelLength == 0 {
					h.WriteByte(0)
					hash = h.Sum64()
					break
				}

				labelLength++
				h.Write(msg[offset : offset+labelLength])
				offset += labelLength
			}
		}

		var (
			fingerprint = takeFingerprint(hash)
			mask        = uint64(len(m.entries) - 1)
			idx         = hash & uint64(mask)
		)

		for !m.entries[idx].isFree() {
			idx = (idx + 1) & mask
		}

		m.available--
		m.entries[idx].fill(fingerprint, entry.ptr())
	}
}
