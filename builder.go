package dnsmsg

import (
	"bytes"
	"errors"
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

	for i := 0; i < len(m); i++ {
		char := m[i]
		switch char {
		case '.':
			buf[labelIndex] = labelLength
			labelLength = 0
			labelIndex = len(buf)
			buf = append(buf, 0)
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

	if explicitEndRoot && buf[len(buf)-1] != 0 {
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

	nb nameBuilderState

	curSection section
	hdr        Header
}

func StartBuilder(buf []byte, id uint16, flags Flags) Builder {
	return Builder{
		buf: append(buf, make([]byte, headerLen)...),
		hdr: Header{
			ID:    id,
			Flags: flags,
		},
	}
}

func (b *Builder) Bytes() []byte {
	b.hdr.pack((*[12]byte)(b.buf[0:12]))
	return b.buf
}

func (b *Builder) StartAnswers() {
	if b.curSection != sectionQuestions {
		panic("invalid section")
	}
	b.curSection = sectionAnswers
}

func (b *Builder) StartAuthority() {
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

func (b *Builder) incQuestionSection() {
	if b.curSection != sectionQuestions {
		panic("invalid section")
	}
	b.hdr.QDCount++
}

func (b *Builder) incResurceSection() {
	switch b.curSection {
	case sectionAnswers:
		b.hdr.ANCount++
	case sectionAuthorities:
		b.hdr.NSCount++
	case sectionAdditionals:
		b.hdr.ARCount++
	default:
		panic("invalid section")
	}
}

func (b *Builder) Question(q Question[RawName]) error {
	return b.appendWithLengthLimit(func() {
		b.incQuestionSection()
		b.buf = b.nb.appendName(b.buf, q.Name, true, true)
		b.buf = appendUint16(b.buf, uint16(q.Type))
		b.buf = appendUint16(b.buf, uint16(q.Class))
	})
}

func (b *Builder) ResourceA(hdr ResourceHeader[RawName], a ResourceA) error {
	return b.appendWithLengthLimit(func() {
		hdr.Length = 4
		b.appendHeader(hdr)
		b.buf = append(b.buf, a.A[:]...)
	})
}

func (b *Builder) ResourceAAAA(hdr ResourceHeader[RawName], aaaa ResourceAAAA) error {
	return b.appendWithLengthLimit(func() {
		hdr.Length = 16
		b.appendHeader(hdr)
		b.buf = append(b.buf, aaaa.AAAA[:]...)
	})
}

func (b *Builder) ResourceCNAME(hdr ResourceHeader[RawName], cname ResourceCNAME[RawName]) error {
	return b.appendWithLengthLimit(func() {
		b.appendResourceAutoLength(hdr, func() {
			b.buf = b.nb.appendName(b.buf, cname.CNAME, true, true)
		})
	})
}

func (b *Builder) ResourceMX(hdr ResourceHeader[RawName], mx ResourceMX[RawName]) error {
	return b.appendWithLengthLimit(func() {
		b.appendResourceAutoLength(hdr, func() {
			b.buf = appendUint16(b.buf, mx.Pref)
			b.buf = b.nb.appendName(b.buf, mx.MX, true, true)
		})
	})
}

var errTXTResourceTooLong = errors.New("too long TXT resource")

func (b *Builder) ResourceTXT(hdr ResourceHeader[RawName], mx ResourceTXT) error {
	if len(mx.TXT) > math.MaxUint16 {
		return errTXTResourceTooLong
	}
	hdr.Length = uint16(len(mx.TXT))
	b.appendHeader(hdr)
	return b.appendWithLengthLimit(func() {
		b.buf = append(b.buf, mx.TXT...)
	})
}

var errMsgTooLong = errors.New("message too long")

func (b *Builder) appendWithLengthLimit(build func()) error {
	buf := b.buf
	build()
	if len(b.buf) > math.MaxUint16 {
		b.buf = buf
		return errMsgTooLong
	}
	return nil
}

func (b *Builder) appendResourceAutoLength(hdr ResourceHeader[RawName], build func()) {
	b.appendHeader(hdr)
	start := len(b.buf)
	build()
	appendUint16(b.buf[start-2:], uint16(len(b.buf)-start))
}

func (b *Builder) appendHeader(hdr ResourceHeader[RawName]) {
	b.incResurceSection()
	b.buf = b.nb.appendName(b.buf, hdr.Name, true, true)
	b.buf = appendUint16(b.buf, uint16(hdr.Type))
	b.buf = appendUint16(b.buf, uint16(hdr.Class))
	b.buf = appendUint32(b.buf, hdr.TTL)
	b.buf = appendUint16(b.buf, hdr.Length)
}

type nameBuilderState struct {
	compression map[string]uint16

	// fastMap is used for small messages to avoid allocating the
	// the compression map and string keys.
	// fastMap is populated when the append function detects that
	// more than one name is being used (in that case the name indicated by
	// firstNameLength must be moved to fastMap or to the compression map,
	// firstNameLength is not even considered when fastMapLength != 0).
	fastMap       fastMap
	fastMapLength uint8

	// This indicates the first name length in the entire message.
	// It is assumed that the name it placed at msg[headerLen:].
	// This field is ignored when the fastMapLength != 0.
	// It used to speed up the builder, when the same name
	// is constantly beeing appended.
	firstNameLength uint8
}

func (b *nameBuilderState) appendName(buf []byte, name RawName, compress, useForCompression bool) []byte {
	if useForCompression && b.firstNameLength == 0 {
		buf = append(buf, name...)
		b.firstNameLength = uint8(len(buf) - headerLen)
		return buf
	}

	if compress {
		return b.appendNameCompress(name, buf, useForCompression)
	}

	return b.appendNameNotCompress(name, buf, useForCompression)
}

const maxPtr = 1<<14 - 1

func (b *nameBuilderState) addToCompressMap(raw []byte, start int) {
	rawAsStr := ""
	for i := 0; raw[i] != 0; i += int(raw[i]) + 1 {
		if start+i <= maxPtr {
			if b.fastMapLength != fastMapMaxLength {
				b.fastMap[b.fastMapLength] = fastMapEntry{
					length: uint8(len(raw[i:])),
					ptr:    uint16(start + i),
				}
				b.fastMapLength++
				continue
			}

			if rawAsStr == "" {
				rawAsStr = string(raw[:])
				if b.compression == nil {
					b.compression = make(map[string]uint16)
				}
			}
			b.compression[rawAsStr[i:]] = uint16(start + i)
		}
	}
}

func (b *nameBuilderState) appendNameNotCompress(name RawName, buf []byte, useForCompression bool) []byte {
	start := len(buf)
	buf = append(buf, name...)

	if useForCompression {
		newName := buf[start:]
		if b.fastMapLength == 0 {
			nameInMsg := buf[headerLen : headerLen+b.firstNameLength]
			if bytes.Equal(nameInMsg, newName) {
				return buf
			}
			b.addToCompressMap(nameInMsg, headerLen)
		}

		// TODO: this should only add names that does not exist yet.
		b.addToCompressMap(newName, start)
	}

	return buf
}

func (b *nameBuilderState) appendNameCompress(name RawName, buf []byte, useForCompression bool) []byte {
	if useForCompression && b.fastMapLength == 0 {
		nameInMsg := buf[headerLen : headerLen+b.firstNameLength]
		if bytes.Equal(nameInMsg, name) {
			return appendUint16(buf, 0xC000|headerLen)
		}
		b.addToCompressMap(nameInMsg, headerLen)
	}

	rawStr := ""

	for i := 0; name[i] != 0; i += int(name[i]) + 1 {
		ptr := b.fastMap.match(b.fastMapLength, buf, name[i:])
		if ptr == 0 && b.compression != nil {
			ptr = b.compression[string(name[i:])]
		}
		if ptr != 0 {
			buf = append(buf, name[:i]...)
			return appendUint16(buf, ptr|0xC000)
		}
		if useForCompression && len(buf)+i <= maxPtr {
			if b.fastMapLength != fastMapMaxLength {
				b.fastMap[b.fastMapLength] = fastMapEntry{
					length: uint8(len(name[i:])),
					ptr:    uint16(len(buf) + i),
				}
				b.fastMapLength++
				continue
			}

			if rawStr == "" {
				rawStr = string(name)
				if b.compression == nil {
					b.compression = make(map[string]uint16)
				}
			}
			b.compression[rawStr[i:]] = uint16(len(buf) + i)
		}
	}
	return append(buf, name...)
}

const fastMapMaxLength = 8

type fastMap [fastMapMaxLength]fastMapEntry

type fastMapEntry struct {
	ptr    uint16
	length uint8
}

func (f *fastMap) match(length uint8, msg []byte, raw []byte) uint16 {
	if bytes.Equal(msg[headerLen:headerLen+f[0].length], raw) {
		return f[0].ptr
	}

	for i := 1; i < int(length); i++ {
		entry := f[i]

		if len(raw) == int(entry.length) {
			msgNameIndex := int(entry.ptr)
			rawNameIndex := 0

			for {
				if msg[msgNameIndex]&0xC0 == 0xC0 {
					msgNameIndex = int(uint16(msg[msgNameIndex]^0xC0)<<8 | uint16(msg[msgNameIndex+1]))
				}

				labelLengthMsg := msg[msgNameIndex]
				labelLengthRaw := raw[rawNameIndex]

				if labelLengthMsg != labelLengthRaw {
					break
				}

				labelLength := labelLengthMsg

				if labelLength == 0 {
					return entry.ptr
				}

				labelMsg := msg[msgNameIndex+1 : 1+msgNameIndex+int(labelLength)]
				labelRaw := raw[rawNameIndex+1 : 1+rawNameIndex+int(labelLength)]
				if !bytes.Equal(labelMsg, labelRaw) {
					break
				}

				msgNameIndex += int(labelLength) + 1
				rawNameIndex += int(labelLength) + 1
			}
		}
	}
	return 0
}
