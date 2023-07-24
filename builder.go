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

func MakeQuery[T RawName | ParserName | Name | SearchName](msg []byte, id uint16, flags Flags, q Question[T]) []byte {
	// Header
	msg = appendUint16(msg, id)
	msg = appendUint16(msg, uint16(flags))
	msg = appendUint16(msg, 1)
	msg = appendUint16(msg, 0)
	msg = appendUint16(msg, 0)
	msg = appendUint16(msg, 0)

	// Question
	msg = appendName(msg, q.Name)
	msg = appendUint16(msg, uint16(q.Type))
	msg = appendUint16(msg, uint16(q.Class))

	return msg
}

func MakeQueryWithEDNS0[T RawName | ParserName | Name | SearchName](msg []byte, id uint16, flags Flags, q Question[T], ends0 EDNS0) []byte {
	// Header
	msg = appendUint16(msg, id)
	msg = appendUint16(msg, uint16(flags))
	msg = appendUint16(msg, 1)
	msg = appendUint16(msg, 0)
	msg = appendUint16(msg, 0)
	msg = appendUint16(msg, 1)

	// Question
	msg = appendName(msg, q.Name)
	msg = appendUint16(msg, uint16(q.Type))
	msg = appendUint16(msg, uint16(q.Class))

	// EDNS0
	msg = append(msg, 0) // root name
	msg = appendUint16(msg, uint16(TypeOPT))
	msg = appendUint16(msg, ends0.Payload)

	// TODO: support rest of EDNS0 stuff.
	msg = appendUint32(msg, 0)
	msg = appendUint16(msg, 0)
	return msg
}

func isZero[T comparable](t T) bool {
	return t == *new(T)
}

func appendName[T RawName | ParserName | Name | SearchName](buf []byte, n T) []byte {
	switch n := any(n).(type) {
	case Name:
		if isZero(n) {
			panic("cannot use zero value of any name type")
		}
		return appendEscapedName(buf, true, n.n)
	case SearchName:
		if isZero(n) {
			panic("cannot use zero value of any name type")
		}
		return appendSearchName(buf, n)
	case ParserName:
		if isZero(n) {
			panic("cannot use zero value of any name type")
		}
		return n.appendRawName(buf)
	case RawName:
		return append(buf, n...)
	default:
		panic("internal error: unsupported name type")
	}
}

var errInvalidName = errors.New("invalid name")

// Name is a wrapper around a string DNS name representation.
// Zero value of this type shouldn't be used, unless specified otherwise.
type Name struct {
	n string
}

func (n Name) AsRawName() RawName {
	return appendEscapedName(make([]byte, 0, maxEncodedNameLen), true, n.n)
}

// NewName creates a new Name.
// The name might contain escape characters like: '\DDD' and '\X',
// where D is a digit and X is any possible character, except digit.
func NewName(name string) (Name, error) {
	if !isValidEscapedName(name) {
		return Name{}, errInvalidName
	}
	return Name{n: name}, nil
}

// MustNewName creates a new Name, panics when it is invalid.
func MustNewName(name string) Name {
	n, err := NewName(name)
	if err != nil {
		panic("MustNewName: " + err.Error())
	}
	return n
}

func (n Name) String() string {
	// TODO: the name can be "unsafe", arbitrary bytes are allowed by
	// NewName, only dots need to be escaped to be treated as the label content
	// maybe this method should check whether the name is unsafe, and when it it
	// make it safe (add escapes properly).
	return n.n
}

func (n Name) IsRooted() bool {
	if n.n[len(n.n)-1] != '.' {
		return false
	}

	endSlashCount := 0
	for i := len(n.n) - 2; i > 0; i-- {
		v := n.n[i]
		if v != '\\' {
			endSlashCount++
			continue
		}
		break
	}

	return endSlashCount%2 != 0
}

func (n Name) labelCount() int {
	count := 0
	if !n.IsRooted() {
		count++
	}

	for i := 0; i < len(n.n); i++ {
		char := n.n[i]
		switch char {
		case '\\':
			i++
			if isDigit(n.n[i]) {
				i += 2
			}
		case '.':
			count++
		}
	}

	return count
}

func (n Name) charCount() int {
	count := 0
	for i := 0; i < len(n.n); i++ {
		char := n.n[i]
		if char == '\\' {
			i++
			if isDigit(n.n[i]) {
				i += 2
			}
		}
		count++
	}
	return count
}

func isValidEscapedName(m string) bool {
	if m == "" {
		return false
	}

	if m == "." {
		return true
	}

	labelLength := 0
	nameLength := 0
	inEscape := false
	rooted := false

	for i := 0; i < len(m); i++ {
		char := m[i]
		rooted = false

		switch char {
		case '.':
			if inEscape {
				labelLength++
				inEscape = false
				continue
			}
			if labelLength == 0 || labelLength > maxLabelLength {
				return false
			}
			rooted = true
			nameLength += labelLength + 1
			labelLength = 0
		case '\\':
			inEscape = !inEscape
			if !inEscape {
				labelLength++
			}
		default:
			if inEscape && isDigit(char) {
				if len(m[i:]) < 3 || !isDigit(m[i+1]) || !isDigit(m[i+2]) {
					return false
				}
				if _, ok := decodeDDD([3]byte{char, m[i+1], m[i+2]}); !ok {
					return false
				}
				i += 2
			}
			inEscape = false
			labelLength++
		}
	}

	if !rooted && labelLength > maxLabelLength {
		return false
	}

	nameLength += labelLength

	if inEscape {
		return false
	}

	if nameLength > 254 || nameLength == 254 && !rooted {
		return false
	}

	return true
}

func appendEscapedName(buf []byte, explicitEndRoot bool, m string) []byte {
	labelLength := byte(0)

	labelIndex := len(buf)
	buf = append(buf, 0)
	lastRoot := false

	if m == "." {
		return buf
	}

	for i := 0; i < len(m); i++ {
		lastRoot = false

		char := m[i]
		switch char {
		case '.':
			buf[labelIndex] = labelLength
			labelLength = 0
			labelIndex = len(buf)
			buf = append(buf, 0)
			lastRoot = true
		case '\\':
			if isDigit(m[i+1]) {
				labelLength++
				ddd, _ := decodeDDD([3]byte{m[i+1], m[i+2], m[i+3]})
				buf = append(buf, ddd)
				i += 3
				continue
			}
			buf = append(buf, m[i+1])
			i += 1
			labelLength++
		default:
			labelLength++
			buf = append(buf, char)
		}
	}

	if labelLength != 0 {
		buf[labelIndex] = labelLength
	}

	if explicitEndRoot && !lastRoot {
		buf = append(buf, 0)
	}

	return buf
}

func isDigit(char byte) bool {
	return char >= '0' && char <= '9'
}

func decodeDDD(ddd [3]byte) (uint8, bool) {
	ddd[0] -= '0'
	ddd[1] -= '0'
	ddd[2] -= '0'
	num := uint16(ddd[0])*100 + uint16(ddd[1])*10 + uint16(ddd[2])
	if num > 255 {
		return 0, false
	}
	return uint8(num), true
}

type SearchNameIterator struct {
	name          Name
	search        []Name
	absoluteFirst bool
	absoluteDone  bool
	done          bool
}

func NewSearchNameIterator(name Name, search []Name, ndots int) SearchNameIterator {
	if name.IsRooted() {
		return SearchNameIterator{name: name}
	}
	return SearchNameIterator{name, search, name.labelCount() >= ndots, false, false}
}

func (s *SearchNameIterator) Next() (SearchName, bool) {
	if s.done {
		return SearchName{}, false
	}

	if !s.absoluteDone && s.absoluteFirst {
		n, err := NewSearchName(Name{}, s.name)
		if err != nil {
			panic("internal error")
		}
		s.absoluteDone = true
		return n, true
	}

	for i, suffix := range s.search {
		name, err := NewSearchName(s.name, suffix)
		if err != nil {
			continue
		}
		s.search = s.search[i+1:]
		return name, false
	}

	if !s.absoluteDone && !s.absoluteFirst {
		n, err := NewSearchName(Name{}, s.name)
		if err != nil {
			panic("internal error")
		}
		s.absoluteDone = true
		s.done = true
		return n, true
	}

	s.done = true
	return SearchName{}, false
}

// SearchName is intended for use with search domains, to avoid
// string concatenations.
// Zero value of this type shouldn't be used.
type SearchName struct {
	prefix Name
	suffix Name
}

func (s SearchName) AsRawName() RawName {
	return appendSearchName(make([]byte, 0, maxEncodedNameLen), s)
}

// NewSearchName creates a new SearchName.
// prefix might be a zero value, then the suffix is
// treated as the entire name, prefix cannot be a rooted name.
func NewSearchName(prefix, suffix Name) (SearchName, error) {
	if !isZero(prefix) && prefix.IsRooted() {
		return SearchName{}, errInvalidName
	}
	nameLength := prefix.charCount() + suffix.charCount()
	if nameLength > 254 || nameLength == 254 && !suffix.IsRooted() {
		return SearchName{}, errInvalidName
	}
	return SearchName{prefix, suffix}, nil
}

func (n SearchName) String() string {
	if isZero(n) {
		return ""
	}
	if isZero(n.prefix) {
		return n.suffix.String()
	}
	return n.prefix.String() + "." + n.suffix.String()
}

func appendSearchName(buf []byte, name SearchName) []byte {
	return appendEscapedName(appendEscapedName(buf, false, name.prefix.n), true, name.suffix.n)
}

type RawName []byte

func NewRawName(name string) (RawName, error) {
	var buf [maxEncodedNameLen]byte
	return newRawName(&buf, name)
}

func MustNewRawName(name string) RawName {
	var buf [maxEncodedNameLen]byte
	return mustNewRawName(&buf, name)
}

func mustNewRawName(buf *[maxEncodedNameLen]byte, name string) RawName {
	if !isValidEscapedName(name) {
		panic("dnsmsg: MustNewName: invalid dns name")
	}
	return appendEscapedName(buf[:0], true, name)
}

func newRawName(buf *[maxEncodedNameLen]byte, name string) (RawName, error) {
	// TODO: merge isValid into appendEscapedName
	if !isValidEscapedName(name) {
		return nil, errInvalidName
	}
	return appendEscapedName(buf[:0], true, name), nil
}

type section uint8

const (
	sectionQuestions section = iota
	sectionAnswers
	sectionAuthorities
	sectionAdditionals
)

// Builder is an incremental DNS message builder.
//
// Internally the Builder contains a building section field, that can be changed
// using one of these methods: [Builder.StartAnswers], [Builder.StartAuthorities], [Builder.StartAdditionals].
// By default the building section is set to questions, it allows appending questions by the
// use of the [Builder.Question] method.
// After changing the building section (using one of the Start* methods described above) the
// resource building methods: ([Builder.ResourceA], [Builder.ResourceAAAA], [Builder.ResourceCNAME],
// [Builder.ResourceMX], [Builder.RawResourceTXT], [Builder.ResourceTXT]), [Builder.SkipResourceData] or
// [Builder.RDBuilder] can be used to append DNS resources.
//
// The zero value of this type shouldn't be used.
type Builder struct {
	buf []byte
	nb  nameBuilderState

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
		maxBufSize:        math.MaxInt,
		hdr: Header{
			ID:    id,
			Flags: flags,
		},
	}
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
	return b.buf
}

// StartAnswers changes the building section from question to answers.
//
// It Panics when the current building section is not questions.
func (b *Builder) StartAnswers() {
	if b.curSection != sectionQuestions {
		panic("invalid section")
	}
	b.curSection = sectionAnswers
}

// StartAuthorities changes the building section from answers to authorities.
//
// It Panics when the current building section is not answers.
func (b *Builder) StartAuthorities() {
	if b.curSection != sectionAnswers {
		panic("invalid section")
	}
	b.curSection = sectionAuthorities
}

// StartAuthorities changes the building section from authorities to additionals.
//
// It Panics when the current building section is not additionals.
func (b *Builder) StartAdditionals() {
	if b.curSection != sectionAuthorities {
		panic("invalid section")
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
		panic("invalid section")
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
func (b *Builder) Question(q Question[RawName]) error {
	if b.curSection != sectionQuestions {
		panic("invalid section")
	}

	if b.hdr.QDCount == math.MaxUint16 {
		return errResourceCountLimitReached
	}

	var err error
	b.buf, err = b.nb.appendName(b.buf, b.maxBufSize-4, b.headerStartOffset, q.Name, true)
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
func (b *Builder) ResourceA(hdr ResourceHeader[RawName], a ResourceA) error {
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
func (b *Builder) ResourceAAAA(hdr ResourceHeader[RawName], aaaa ResourceAAAA) error {
	hdr.Length = 16
	if err := b.appendHeader(hdr, b.maxBufSize-16); err != nil {
		return err
	}
	b.buf = append(b.buf, aaaa.AAAA[:]...)
	return nil
}

// ResourceCNAME appends a single CNAME resource.
// It errors when the amount of resources in the current section is equal to 65535.
//
// The building section must NOT be set to questions, otherwise it panics.
func (b *Builder) ResourceCNAME(hdr ResourceHeader[RawName], cname ResourceCNAME[RawName]) error {
	f, hdrOffset, err := b.appendHeaderWithLengthFixup(hdr, b.maxBufSize)
	if err != nil {
		return err
	}
	b.buf, err = b.nb.appendName(b.buf, b.maxBufSize, b.headerStartOffset, cname.CNAME, true)
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
func (b *Builder) ResourceMX(hdr ResourceHeader[RawName], mx ResourceMX[RawName]) error {
	f, hdrOffset, err := b.appendHeaderWithLengthFixup(hdr, b.maxBufSize-2)
	if err != nil {
		return err
	}
	b.buf = appendUint16(b.buf, mx.Pref)
	b.buf, err = b.nb.appendName(b.buf, b.maxBufSize, b.headerStartOffset, mx.MX, true)
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
func (b *Builder) RawResourceTXT(hdr ResourceHeader[RawName], txt RawResourceTXT) error {
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

var errTooLongTXTString = errors.New("too long txt string")
var errTooLongTXT = errors.New("too long txt resource")

// ResourceTXT appends a single TXT resource.
// It errors when the amount of resources in the current section is equal to 65535.
//
// The building section must NOT be set to questions, otherwise it panics.
func (b *Builder) ResourceTXT(hdr ResourceHeader[RawName], txt ResourceTXT) error {
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

func (b *Builder) appendHeader(hdr ResourceHeader[RawName], maxBufSize int) error {
	if err := b.incResurceSection(); err != nil {
		return err
	}
	var err error
	b.buf, err = b.nb.appendName(b.buf, maxBufSize-10, b.headerStartOffset, hdr.Name, true)
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

func (b *Builder) appendHeaderWithLengthFixup(hdr ResourceHeader[RawName], maxBufSize int) (headerLengthFixup, int, error) {
	err := b.incResurceSection()
	if err != nil {
		return 0, 0, err
	}
	nameOffset := len(b.buf)
	b.buf, err = b.nb.appendName(b.buf, maxBufSize-10, b.headerStartOffset, hdr.Name, true)
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

func (b *Builder) removeResourceHeader(headerOffset int) {
	b.nb.removeNamesFromCompressionMap(b.headerStartOffset, headerOffset)
	b.buf = b.buf[:headerOffset]
	b.decResurceSection()
}

// RDParser is a resource data builder used to build custom resources.
//
// Note: The returned RDBuilder should not be used after creating any new resource in the [Builder].
// Once a resource is created using the RDBuilder, attempting to use the same RDBuilder again might lead to panics.
type RDBuilder struct {
	b         *Builder
	fixup     headerLengthFixup
	hdrOffset int
}

func (b *RDBuilder) isCallValid() {
	if b.fixup.rDataLength(b.b) != int(b.fixup.currentlyStoredLength(b.b)) {
		panic("dnsmsg: Invalid usage of RDBuilder. It is not allowed to modify the resource data after creating a new resource.")
	}
}

var errResourceTooLong = errors.New("too long resource")

// Length returns the current length of the resource data in bytes.
func (b *RDBuilder) Length() int {
	b.isCallValid()
	return b.fixup.rDataLength(b.b)
}

// Remove removes the resource from the message.
func (b *RDBuilder) Remove() {
	b.isCallValid()
	b.b.removeResourceHeader(b.hdrOffset)
}

// Name appends a DNS name to the resource data.
//
// If the resource data exceeds the maximum allowed size of 64 KiB or the message limit size
// is reached ([Builder.LimitMessageSize]), an error will be returned.
// Note: In case of an error, the resource is not removed, and you can still use the RDBuilder safely.
// The Resource can be removed via the [RDBuilder.Remove] method.
func (b *RDBuilder) Name(name RawName, compress bool) error {
	b.isCallValid()

	nameOffset := len(b.b.buf)
	var err error
	b.b.buf, err = b.b.nb.appendName(b.b.buf, b.b.maxBufSize, b.b.headerStartOffset, name, compress)
	if err != nil {
		return err
	}

	if b.fixup.rDataLength(b.b) > math.MaxUint16 {
		b.b.nb.removeNamesFromCompressionMap(b.b.headerStartOffset, nameOffset)
		b.b.buf = b.b.buf[:nameOffset]
		return errResourceTooLong
	}

	b.fixup.fixup(b.b)
	return nil
}

// Bytes appends a raw byte slice to the resource data.
//
// If the resource data exceeds the maximum allowed size of 64 KiB or the message limit size
// is reached ([Builder.LimitMessageSize]), an error will be returned.
// Note: In case of an error, the resource is not removed, and you can still use the RDBuilder safely.
// The Resource can be removed via the [RDBuilder.Remove] method.
func (b *RDBuilder) Bytes(raw []byte) error {
	b.isCallValid()
	if b.Length()+len(raw) > math.MaxUint16 {
		return errResourceTooLong
	}
	if len(b.b.buf)+len(raw) > b.b.maxBufSize {
		return ErrTruncated
	}
	b.b.buf = append(b.b.buf, raw...)
	b.fixup.fixup(b.b)
	return nil
}

// Uint8 appends a single uint8 value to the resource data.
//
// If the resource data exceeds the maximum allowed size of 64 KiB or the message limit size
// is reached ([Builder.LimitMessageSize]), an error will be returned.
// Note: In case of an error, the resource is not removed, and you can still use the RDBuilder safely.
// The Resource can be removed via the [RDBuilder.Remove] method.
func (b *RDBuilder) Uint8(val uint8) error {
	b.isCallValid()
	if b.Length()+1 > math.MaxUint16 {
		return errResourceTooLong
	}
	if len(b.b.buf)+1 > b.b.maxBufSize {
		return ErrTruncated
	}
	b.b.buf = append(b.b.buf, val)
	b.fixup.fixup(b.b)
	return nil
}

// Uint16 appends a single uint16 value to the resource data in Big-Endian format.
//
// If the resource data exceeds the maximum allowed size of 64 KiB or the message limit size
// is reached ([Builder.LimitMessageSize]), an error will be returned.
// Note: In case of an error, the resource is not removed, and you can still use the RDBuilder safely.
// The Resource can be removed via the [RDBuilder.Remove] method.
func (b *RDBuilder) Uint16(val uint16) error {
	b.isCallValid()
	if b.Length()+2 > math.MaxUint16 {
		return errResourceTooLong
	}
	if len(b.b.buf)+2 > b.b.maxBufSize {
		return ErrTruncated
	}
	b.b.buf = appendUint16(b.b.buf, val)
	b.fixup.fixup(b.b)
	return nil
}

// Uint32 appends a single uint16 value to the resource data in Big-Endian format.
//
// If the resource data exceeds the maximum allowed size of 64 KiB or the message limit size
// is reached ([Builder.LimitMessageSize]), an error will be returned.
// Note: In case of an error, the resource is not removed, and you can still use the RDBuilder safely.
// The Resource can be removed via the [RDBuilder.Remove] method.
func (b *RDBuilder) Uint32(val uint32) error {
	b.isCallValid()
	if b.Length()+4 > math.MaxUint16 {
		return errResourceTooLong
	}
	if len(b.b.buf)+4 > b.b.maxBufSize {
		return ErrTruncated
	}
	b.b.buf = appendUint32(b.b.buf, val)
	b.fixup.fixup(b.b)
	return nil
}

// Uint64 appends a single uint16 value to the resource data in Big-Endian format.
//
// If the resource data exceeds the maximum allowed size of 64 KiB or the message limit size
// is reached ([Builder.LimitMessageSize]), an error will be returned.
// Note: In case of an error, the resource is not removed, and you can still use the RDBuilder safely.
// The Resource can be removed via the [RDBuilder.Remove] method.
func (b *RDBuilder) Uint64(val uint64) error {
	b.isCallValid()
	if b.Length()+8 > math.MaxUint16 {
		return errResourceTooLong
	}
	if len(b.b.buf)+8 > b.b.maxBufSize {
		return ErrTruncated
	}
	b.b.buf = appendUint64(b.b.buf, val)
	b.fixup.fixup(b.b)
	return nil
}

// RDBuilder craeates a new [RDBuilder], used for building custom resource data.
// It errors when the amount of resources in the current section is equal to 65535.
//
// Note: The returned RDBuilder should not be used after creating any new resource in b.
// Once a resource is created using the RDBuilder, attempting to use the same RDBuilder again might lead to panics.
//
// The building section must NOT be set to questions, otherwise it panics.
func (b *Builder) RDBuilder(hdr ResourceHeader[RawName]) (RDBuilder, error) {
	hdr.Length = 0
	f, hdrOffset, err := b.appendHeaderWithLengthFixup(hdr, b.maxBufSize)
	if err != nil {
		return RDBuilder{}, err
	}
	return RDBuilder{
		b:         b,
		fixup:     f,
		hdrOffset: hdrOffset,
	}, nil
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
				if int(m.ptr()) < len(msg) {
					msgNameIndex := int(m.ptr())
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

		newPtr := len(msg) + i
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
	if namesStartOffset == headerLen+headerStartOffset {
		m.firstNameLength = 0
		return
	}
	if namesStartOffset <= maxPtr {
		m.invalidPtrsAfter = uint16(namesStartOffset)
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
