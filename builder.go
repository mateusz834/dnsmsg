package dnsmsg

import (
	"bytes"
	"errors"
	"hash/maphash"
	"math"
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
	name   Name
	suffix Name
}

func (s SearchName) AsRawName() RawName {
	return appendSearchName(make([]byte, 0, maxEncodedNameLen), s)
}

// NewSearchName creates a new SearchName.
// name might be a zero value, then the suffix is
// treated as the entire name, name cannot be a rooted name.
func NewSearchName(name, suffix Name) (SearchName, error) {
	if !isZero(name) && name.IsRooted() {
		return SearchName{}, errInvalidName
	}
	nameLength := name.charCount() + suffix.charCount()
	if nameLength > 254 || nameLength == 254 && !suffix.IsRooted() {
		return SearchName{}, errInvalidName
	}
	return SearchName{name, suffix}, nil
}

func (n SearchName) String() string {
	if isZero(n) {
		return ""
	}
	if isZero(n.name) {
		return n.suffix.String()
	}
	return n.name.String() + "." + n.suffix.String()
}

func appendSearchName(buf []byte, name SearchName) []byte {
	return appendEscapedName(appendEscapedName(buf, false, name.name.n), true, name.suffix.n)
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

type Builder struct {
	buf []byte
	nb  nameBuilderState

	headerStartOffset int

	curSection section
	hdr        Header
}

func StartBuilder(buf []byte, id uint16, flags Flags) Builder {
	return Builder{
		headerStartOffset: len(buf),
		buf:               append(buf, make([]byte, headerLen)...),
		hdr: Header{
			ID:    id,
			Flags: flags,
		},
	}
}

func (b *Builder) Reset(buf []byte, id uint16, flags Flags) {
	nb := b.nb
	nb.reset()
	*b = StartBuilder(buf, id, flags)
	b.nb = nb
}

func (b *Builder) Bytes() []byte {
	b.hdr.pack((*[12]byte)(b.buf[b.headerStartOffset:]))
	return b.buf
}

func (b *Builder) StartAnswers() {
	if b.curSection != sectionQuestions {
		panic("invalid section")
	}
	b.curSection = sectionAnswers
}

func (b *Builder) StartAuthorities() {
	if b.curSection != sectionAnswers {
		panic("invalid section")
	}
	b.curSection = sectionAuthorities
}

func (b *Builder) StartAdditionals() {
	if b.curSection != sectionAuthorities {
		panic("invalid section")
	}
	b.curSection = sectionAdditionals
}

var errResourceCountLimitReached = errors.New("maximum amount of DNS resources/questions reached")

func (b *Builder) incQuestionSection() error {
	if b.curSection != sectionQuestions {
		panic("invalid section")
	}
	if b.hdr.QDCount == math.MaxUint16 {
		return errResourceCountLimitReached
	}
	b.hdr.QDCount++
	return nil
}

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

func (b *Builder) Question(q Question[RawName]) error {
	if err := b.incQuestionSection(); err != nil {
		return err
	}
	b.buf = b.nb.appendName(b.buf, b.headerStartOffset, q.Name, true)
	b.buf = appendUint16(b.buf, uint16(q.Type))
	b.buf = appendUint16(b.buf, uint16(q.Class))
	return nil
}

func (b *Builder) ResourceA(hdr ResourceHeader[RawName], a ResourceA) error {
	hdr.Length = 4
	if err := b.appendHeader(hdr); err != nil {
		return err
	}
	b.buf = append(b.buf, a.A[:]...)
	return nil
}

func (b *Builder) ResourceAAAA(hdr ResourceHeader[RawName], aaaa ResourceAAAA) error {
	hdr.Length = 16
	if err := b.appendHeader(hdr); err != nil {
		return err
	}
	b.buf = append(b.buf, aaaa.AAAA[:]...)
	return nil
}

func (b *Builder) ResourceCNAME(hdr ResourceHeader[RawName], cname ResourceCNAME[RawName]) error {
	f, err := b.appendHeaderWithLengthFixup(hdr)
	if err != nil {
		return err
	}
	b.buf = b.nb.appendName(b.buf, b.headerStartOffset, cname.CNAME, true)
	f.fixup(b)
	return nil
}

func (b *Builder) ResourceMX(hdr ResourceHeader[RawName], mx ResourceMX[RawName]) error {
	f, err := b.appendHeaderWithLengthFixup(hdr)
	if err != nil {
		return err
	}
	b.buf = appendUint16(b.buf, mx.Pref)
	b.buf = b.nb.appendName(b.buf, b.headerStartOffset, mx.MX, true)
	f.fixup(b)
	return nil
}

var errInvalidRawTXTResource = errors.New("invalid raw txt resource")

func (b *Builder) RawResourceTXT(hdr ResourceHeader[RawName], txt RawResourceTXT) error {
	if len(txt.TXT) > math.MaxUint16 || !txt.isValid() {
		return errInvalidRawTXTResource
	}

	hdr.Length = uint16(len(txt.TXT))
	if err := b.appendHeader(hdr); err != nil {
		return err
	}
	b.buf = append(b.buf, txt.TXT...)
	return nil
}

var errTooLongTXTString = errors.New("too long txt string")
var errTooLongTXT = errors.New("too long txt resource")

func (b *Builder) ResourceTXT(hdr ResourceHeader[RawName], txt ResourceTXT) error {
	totalLength := 0
	for _, str := range txt.TXT {
		if len(str) > math.MaxUint8 {
			return errTooLongTXTString
		}
		totalLength += len(str)
		if totalLength > math.MaxUint16 {
			return errTooLongTXT
		}
	}

	hdr.Length = uint16(totalLength)
	if err := b.appendHeader(hdr); err != nil {
		return err
	}

	for _, str := range txt.TXT {
		b.buf = append(b.buf, uint8(len(str)))
		b.buf = append(b.buf, str...)
	}

	return nil
}

func (b *Builder) appendHeader(hdr ResourceHeader[RawName]) error {
	if err := b.incResurceSection(); err != nil {
		return err
	}
	b.buf = b.nb.appendName(b.buf, b.headerStartOffset, hdr.Name, true)
	b.buf = appendUint16(b.buf, uint16(hdr.Type))
	b.buf = appendUint16(b.buf, uint16(hdr.Class))
	b.buf = appendUint32(b.buf, hdr.TTL)
	b.buf = appendUint16(b.buf, hdr.Length)
	return nil
}

type headerLengthFixup int

func (f headerLengthFixup) fixup(b *Builder) {
	packUint16(b.buf[f-2:], uint16(len(b.buf)-int(f)))
}

func (b *Builder) appendHeaderWithLengthFixup(hdr ResourceHeader[RawName]) (headerLengthFixup, error) {
	if err := b.incResurceSection(); err != nil {
		return 0, err
	}
	b.buf = b.nb.appendName(b.buf, b.headerStartOffset, hdr.Name, true)
	b.buf = appendUint16(b.buf, uint16(hdr.Type))
	b.buf = appendUint16(b.buf, uint16(hdr.Class))
	b.buf = appendUint32(b.buf, hdr.TTL)
	b.buf = appendUint16(b.buf, hdr.Length)
	return headerLengthFixup(len(b.buf)), nil
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

type nameBuilderState struct {
	entries         []entry
	available       int
	seed            maphash.Seed
	firstNameLength uint8
}

func (c *nameBuilderState) reset() {
	for i := range c.entries {
		c.entries[i] = 0
	}
	c.available = len(c.entries)
	c.firstNameLength = 0
}

func (m *nameBuilderState) appendName(msg []byte, headerStartOffset int, name []byte, compress bool) []byte {
	if m.firstNameLength == 0 {
		m.firstNameLength = uint8(len(name))
		return append(msg, name...)
	}

	if len(name) == 1 {
		return append(msg, 0)
	}

	firstName := msg[headerLen+headerStartOffset:][:m.firstNameLength]
	if compress && bytes.Equal(firstName, name) {
		return appendUint16(msg, headerLen|0xC000)
	}

	for i := 0; name[i] != 0; i += int(name[i]) + 1 {
		startOffset := len(firstName) - len(name[i:])
		if compress && startOffset >= 0 && bytes.Equal(firstName[startOffset:], name[i:]) {
			msg = append(msg, name[:i]...)
			return appendUint16(msg, 0xC000|(headerLen+uint16(startOffset)))
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
							return appendUint16(msg, m.ptr()|0xC000)
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
	return append(msg, name...)
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
