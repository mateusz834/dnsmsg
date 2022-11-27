package dnsmsg

import (
	"math"
	"unsafe"
)

func appendName(buf []byte, name *BuilderName) ([]byte, error) {
	switch name := name.val.(type) {
	case rootName:
		return append(buf, 0), nil
	case rawName:
		return append(buf, name...), nil
	case string:
		return appendHumanName(buf, name)
	case []byte:
		return appendHumanName(buf, name)
	default:
		panic("aa TODO")
	}
}

// BuilderName should be used ONLY with the same builder, reusing them
// between different builder might cause a unexpected behaviour.
type BuilderName struct {
	val    any
	inMsg  bool
	offset uint16
}

type rawName []byte
type rootName struct{}

func NewStringName(name string) *BuilderName {
	if len(name) == 1 && name[0] == '.' {
		return &BuilderName{val: rootName{}}
	}
	return &BuilderName{val: name}
}

func NewBytesName(name []byte) *BuilderName {
	if len(name) == 1 && name[0] == '.' {
		return &BuilderName{val: rootName{}}
	}
	return &BuilderName{val: name}
}

func NewRawName(name []byte) *BuilderName {
	if len(name) == 1 && name[0] == 0 {
		return &BuilderName{val: rootName{}}
	}
	return &BuilderName{val: rawName(name)}
}

// Name appends the name to the message.
func (b *Builder) Name(n *BuilderName) error {
	// This implementation is done in such way to not use the b.m map
	// while building messages with the same name.

	// Don't even try to compress root names.
	if _, ok := n.val.(rootName); ok {
		b.buf = append(b.buf, 0)
		return nil
	}

	if b.oneSameName && b.m == nil {
		if n.inMsg {
			b.buf = appendUint16(b.buf, 0xC000|n.offset)
			return nil
		}

		// We got different name, allocate hash map and populate it
		b.m = getMap()
		rawNameStr := string(b.buf[n.offset:b.firstNameEnd])
		for i := 0; i < len(rawNameStr) && rawNameStr[i] != 0; i += int(rawNameStr[i]) + 1 {
			b.m[rawNameStr[i:]] = n.offset + uint16(i)
		}
	}

	offset := b.getOffset()

	if !b.oneSameName {
		b.oneSameName = true

		switch name := n.val.(type) {
		case rawName:
			b.buf = append(b.buf, name...)
		case string:
			var err error
			b.buf, err = appendHumanName(b.buf, name)
			if err != nil {
				return err
			}
		case []byte:
			var err error
			b.buf, err = appendHumanName(b.buf, name)
			if err != nil {
				return err
			}
		}

		b.firstNameEnd = uint16(len(b.buf))
		n.inMsg = true
		n.offset = offset
		return nil
	}

	if n.inMsg && n.offset != invalidOffset {
		b.buf = appendUint16(b.buf, 0xC000|n.offset)
		return nil
	}

	var raw string
	switch name := n.val.(type) {
	case rawName:
		raw = string(name)
	case string:
		r, err := appendHumanName(make([]byte, 0, estimateRawLen(name)), name)
		if err != nil {
			return err
		}

		// TODO: maybe we can create directly a string using string.Builder??
		// TODO: it will not be easy, we can't write to specific index in string.Builder
		// TOOD: so we will have to do it diffetently than appendHumanName does.
		raw = *(*string)(unsafe.Pointer(&r))
	case []byte:
		r, err := appendHumanName(make([]byte, 0, estimateRawLen(name)), name)
		if err != nil {
			return err
		}
		raw = string(r)
	default:
		panic("cannot use zero value of BuilderName")
	}

	// Try to compress the name.
	for i := 0; i < len(raw) && raw[i] != 0; i += int(raw[i]) + 1 {
		ptr, ok := b.m[raw[i:]]
		if ok {
			b.buf = append(b.buf, raw[:i]...)
			b.buf = appendUint16(b.buf, 0xC000|ptr)
			n.inMsg = true
			n.offset = offset
			return nil
		}

		// Update the map only when the pointer to
		// this name fits in 14 bits.
		if int(offset)+i <= maxPtrOffset {
			b.m[raw[i:]] = offset + uint16(i)
		}
	}

	b.buf = append(b.buf, raw...)
	n.inMsg = true
	n.offset = offset
	return nil
}

const (
	// 14 bits set to one
	maxPtrOffset  = math.MaxUint16 & ^(0xC000)
	invalidOffset = math.MaxUint16
)

func (b *Builder) getOffset() uint16 {
	off := len(b.buf)
	if off > maxPtrOffset {
		return invalidOffset
	}
	return uint16(off)
}

const maxNameLen = 255

func appendHumanName[T []byte | string](buf []byte, m T) ([]byte, error) {
	if len(m) == 0 {
		return nil, errInvalidDNSName
	}

	startLen := len(buf)
	lengthIndex := len(buf)

	buf = append(buf, 0)

loop:
	for i := 0; i < len(m); i++ {
		char := m[i]

		switch char {
		case '.':
			// last ending dot
			if len(m) == i+1 {
				break loop
			}

			lengthIndex = len(buf)
			buf = append(buf, 0)
			continue
		case '\\':
			if len(m) == i+1 {
				return nil, errInvalidDNSName
			}
			i++
			char = m[i]

			if char >= '0' && char <= '9' {
				if len(m) == i+1 || len(m) == i+2 {
					return nil, errInvalidDNSName
				}

				if !(m[i+1] >= '0' && m[i+1] <= '9' && m[i+2] >= '0' && m[i+2] <= '9') {
					return nil, errInvalidDNSName
				}

				tmp := (uint16(char)-'0')*100 + (uint16(m[i+1])-'0')*10 + (uint16(m[i+2]) - '0')
				i += 2

				if tmp > math.MaxUint8 {
					return nil, errInvalidDNSName
				}
				char = uint8(tmp)
			}
		}
		buf = append(buf, char)
		buf[lengthIndex]++
		if buf[lengthIndex] > 63 {
			return nil, errInvalidDNSName
		}
	}

	buf = append(buf, 0)
	if len(buf)-startLen > int(maxNameLen) {
		return nil, errInvalidDNSName
	}
	return buf, nil
}

// estimateRawLen estimates the length of the name as if it was encoded
// using the DNS message encoding. It only estimates, we don't take into account
// possible escapes like `\DDD` and `\.`, because they are rarely used.
func estimateRawLen[T string | []byte](name T) int {
	if len(name) == 0 {
		return 0
	}

	nameLen := len(name)
	if name[len(name)-1] == '.' {
		nameLen--
	}

	if nameLen == 0 {
		return 1
	}

	if nameLen+2 > maxNameLen {
		return maxNameLen
	}

	// We add 2 more bytes, insted of 1, because of possible one label names.
	// For "sth.test" we only need len("sth.test") + 1, but to
	// encode "test" we need len("test") + 2 bytes.
	return nameLen + 2
}
