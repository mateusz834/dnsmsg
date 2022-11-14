package dnsmsg

import (
	"math"
	"unsafe"
)

type BuilderNameBuilder struct {
	cmprMap map[string]uint16
}

func (b *BuilderNameBuilder) NameRaw(s []byte) BuilderName {
	for i := 0; i < len(s); i += int(s[i]) {
		if s[i] == 0 {
			break
		}

		name := s[i:]
		v, ok := b.cmprMap[string(name)]
		if ok {
			if i == 0 {
				return NewPtrName(v)
			}
			return NewRawNameWithPtr(s[:i], v)
		}
		b.cmprMap[string(name)] = 0
	}
	return NewRawName(s)
}

/*
func (b *Builder) Name(n *BuilderName) error {

	switch n.ptrType {
	default:
		// splitted to allow Name() to be inlined, so that NewRawName()
		// will be tha fastest one.
		return b.nameRest(n)
	}
}
*/

func (b *Builder) Name(n *BuilderName) (err error) {
	n.msgOffset = uint16(len(b.buf))

	switch n.ptrType {
	case ptrTypeRoot:
		b.buf = append(b.buf, 0)
	case ptrTypePtr:
		b.buf = appendUint16(b.buf, n.cmprPtr)

	case ptrTypeRaw:
		b.buf = append(b.buf, *(*[]byte)(n.ptr)...)
		return nil
	case ptrTypeRawWithPtr:
		b.buf = append(b.buf, *(*[]byte)(n.ptr)...)
		b.buf = appendUint16(b.buf, n.cmprPtr)
	case ptrTypeRawPtrToNameBuilder:
		ptr := (*ptrFromBuilderName)(n.ptr)
		if !ptr.b.inMsg {
			panic("cannot point to a non-yet builded name")
		}
		b.buf = append(b.buf, *ptr.raw...)
		b.buf = appendUint16(b.buf, (ptr.b.msgOffset+n.cmprPtr)|0xC000)

	case ptrTypeString:
		b.buf, err = appendHumanName(b.buf, *(*string)(n.ptr))
	case ptrTypeStringAutoCompress:
		acs := (*autoCompressString)(n.ptr)
		b.buf, err = acs.cnb.packCompress(b.buf, *acs.s)

	case ptrTypeBytes:
		b.buf, err = appendHumanName(b.buf, *(*[]byte)(n.ptr))
	default:
		panic("cannot use zero value of BuilderName")
	}

	n.inMsg = true
	return err
}

// TODO: rename that
type ptrFromBuilderName struct {
	b   *BuilderName
	raw *[]byte
}

type ptrType uint8

const (
	ptrTypeUnknown ptrType = iota

	ptrTypeRaw
	ptrTypeRawWithPtr
	ptrTypeRawPtrToNameBuilder

	ptrTypeString
	ptrTypeStringAutoCompress

	ptrTypeBytes
	ptrTypeRoot
	ptrTypePtr
)

type autoCompressString struct {
	cnb *CompressionNameBuilder
	s   *string
}

type CompressionNameBuilder struct {
	m map[string]uint16
}

func (b *CompressionNameBuilder) NewStringName(name string) BuilderName {
	return BuilderName{
		ptr: unsafe.Pointer(&autoCompressString{
			cnb: b,
			s:   &name,
		}),
		ptrType: ptrTypeStringAutoCompress,
	}
}

func (b *CompressionNameBuilder) packCompress(buf []byte, name string) ([]byte, error) {
	if name == "." {
		return append(buf, 0), nil
	}

	encodedName, err := appendHumanName(buf[len(buf):], name)
	if err != nil {
		return nil, err
	}

	for i := 0; i < len(encodedName) && encodedName[i] != 0; i += int(encodedName[i]) + 1 {
		v, ok := b.m[string(encodedName[i:])]
		if ok {
			if i != 0 {
				b.m[string(encodedName)] = uint16(len(buf))
			}
			buf = append(buf, encodedName[:i]...)
			buf = appendUint16(buf, 0xC000|v)
			return buf, nil
		}
	}

	b.m[string(encodedName)] = uint16(len(buf))
	return buf[:len(buf)+len(encodedName)], nil
}

//TODO: zamiast addOff można dodać skipLabelCount teź

func NewRawNamePtrTo(raw []byte, ptrTo *BuilderName, addOff uint16) BuilderName {
	return BuilderName{
		ptr: unsafe.Pointer(&ptrFromBuilderName{
			b:   ptrTo,
			raw: &raw,
		}),
		ptrType: ptrTypeRawPtrToNameBuilder,
		cmprPtr: addOff,
	}
}

type BuilderName struct {
	// We are using unsafe.Pointer, because while using interfaces we cause
	// a lot of heap allocations, which we want to avoid in this package.
	ptr       unsafe.Pointer
	ptrType   ptrType
	inMsg     bool
	cmprPtr   uint16
	msgOffset uint16
}

func (b *BuilderName) MsgOffset() uint16 {
	return b.msgOffset
}

func NewRawName(raw []byte) BuilderName {
	return BuilderName{
		ptr:     unsafe.Pointer(&raw),
		ptrType: ptrTypeRaw,
	}
}

func NewRawNameWithPtr(raw []byte, ptr uint16) BuilderName {
	return BuilderName{
		ptr:     unsafe.Pointer(&raw),
		ptrType: ptrTypeRawWithPtr,
		cmprPtr: ptr | 0xC000,
	}
}

func NewStringName(name string) BuilderName {
	return BuilderName{
		ptr:     unsafe.Pointer(&name),
		ptrType: ptrTypeString,
	}
}

func NewBytesName(name []byte) BuilderName {
	return BuilderName{
		ptr:     unsafe.Pointer(&name),
		ptrType: ptrTypeBytes,
	}
}

func NewRootName() BuilderName {
	return BuilderName{
		ptrType: ptrTypeRoot,
	}
}

func NewPtrName(ptr uint16) BuilderName {
	return BuilderName{
		ptrType: ptrTypePtr,
		cmprPtr: ptr | 0xC000,
	}
}

const maxNameLen = 255

func appendHumanName[T []byte | string](buf []byte, m T) ([]byte, error) {
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
	if len(buf)-startLen > maxNameLen {
		return nil, errInvalidDNSName
	}
	return buf, nil
}
