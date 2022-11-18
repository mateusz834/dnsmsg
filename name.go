package dnsmsg

import (
	"math"
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

// BuilderName should be used only within the same builder, reusing them
// between different builder might cause a unexpected behaviour.
type BuilderName struct {
	val   any
	inMsg bool
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
	// This implementation is done in such way not to use the b.m map
	// while building messages with the same name.

	// Don't even try to compress root names.
	if _, ok := n.val.(rootName); ok {
		b.buf = append(b.buf, 0)
		return nil
	}

	if b.oneSameName && b.m == nil {
		if n.inMsg {
			b.buf = appendUint16(b.buf, 0xC000|b.firstNameOffset)
			return nil
		}

		// We got different name, allocate hash map and populate it
		b.m = make(map[string]uint16)
		rawNameStr := string(b.buf[b.firstNameOffset:b.firstNameEnd])
		for i := 0; i < len(rawNameStr) && rawNameStr[i] != 0; i += int(rawNameStr[i]) + 1 {
			b.m[rawNameStr[i:]] = b.firstNameOffset + uint16(i)
		}

		/*
			switch name := n.val.(type) {
			case rawName:
				if equalRaw(b.buf, b.firstNameOffset, name) {
					b.buf = appendUint16(b.buf, 0xC000|b.firstNameOffset)
					return nil
				}

				b.m = make(map[string]uint16)
				rawNameStr := string(name)
				for i := 0; i < len(rawNameStr) && rawNameStr[i] != 0; i += int(rawNameStr[i]) + 1 {
					b.m[rawNameStr[i:]] = b.firstNameOffset + uint16(i)
				}
			}
		*/
	}

	b.firstNameOffset = uint16(len(b.buf))

	if !b.oneSameName {
		b.oneSameName = true
		n.inMsg = true
		var err error

		switch name := n.val.(type) {
		case rawName:
			b.buf = append(b.buf, name...)
		case string:
			b.buf, err = appendHumanName(b.buf, name)
		case []byte:
			b.buf, err = appendHumanName(b.buf, name)
		}

		b.firstNameEnd = uint16(len(b.buf))
		return err
	}

	var raw string

	switch name := n.val.(type) {
	case rawName:
		raw = string(name)
	case string:
		r, err := appendHumanName(make([]byte, 0, len(name)), name)
		if err != nil {
			return err
		}

		// TODO: check if this allocates ...
		// TODO: maybe we can create directly a string using string.Builder??
		raw = string(r)
	case []byte:
		r, err := appendHumanName(make([]byte, 0, len(name)), name)
		if err != nil {
			return err
		}
		raw = string(r)
	default:
		panic("cannot use zero value of BuilderName")
	}

	for i := 0; i < len(raw) && raw[i] != 0; i += int(raw[i]) + 1 {
		ptr, ok := b.m[raw[i:]]
		if ok {
			b.buf = append(b.buf, raw[:i]...)
			b.buf = appendUint16(b.buf, 0xC000|ptr)
			return nil
		}
		b.m[raw[i:]] = b.firstNameOffset + uint16(i)
	}

	b.buf = append(b.buf, raw...)
	return nil
}

const maxNameLen = 255

func appendHumanName[T []byte | string](buf []byte, m T) ([]byte, error) {
	if len(m) == 0 {
		return nil, errInvalidDNSName
	}

	startLen := len(buf)
	buf = append(buf, 0)
	length := &buf[len(buf)-1]

loop:
	for i := 0; i < len(m); i++ {
		char := m[i]

		switch char {
		case '.':
			// last ending dot
			if len(m) == i+1 {
				break loop
			}

			buf = append(buf, 0)
			length = &buf[len(buf)-1]
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
		*length++
		if *length > 63 {
			return nil, errInvalidDNSName
		}
	}

	buf = append(buf, 0)
	if len(buf)-startLen > int(maxNameLen) {
		return nil, errInvalidDNSName
	}
	return buf, nil
}
