package dnsmsg

import (
	"math"
	"unsafe"
)

func (b *Builder) Name(n BuilderName) error {
	switch n.ptrType {
	case ptrTypeRaw:
		b.buf = append(b.buf, *(*[]byte)(n.ptr)...)
		return nil
	default:
		// splitted to allow Name() to be inlined, so that NewRawName()
		// will be tha fastest one.
		return b.nameRest(n)
	}
}

func (b *Builder) nameRest(n BuilderName) (err error) {
	switch n.ptrType {
	case ptrTypeRoot:
		b.buf = append(b.buf, 0)
	case ptrTypePtr:
		b.buf = appendUint16(b.buf, n.cmprPtr)
	case ptrTypeString:
		b.buf, err = appendHumanName(b.buf, *(*string)(n.ptr))
	case ptrTypeBytes:
		b.buf, err = appendHumanName(b.buf, *(*[]byte)(n.ptr))
	default:
		panic("cannot use zero value of BuilderName")
	}
	return err
}

type ptrType uint8

const (
	ptrTypeUnknown ptrType = iota
	ptrTypeRaw
	ptrTypeString
	ptrTypeBytes
	ptrTypeRoot
	ptrTypePtr
)

type BuilderName struct {
	// We are using unsafe.Pointer, because while using interfaces we cause
	// a lot of heap allocations, which we want to avoid in this package.
	ptr     unsafe.Pointer
	ptrType ptrType
	cmprPtr uint16
}

func NewRawName(raw []byte) BuilderName {
	return BuilderName{
		ptr:     unsafe.Pointer(&raw),
		ptrType: ptrTypeRaw,
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
