package dnsmsg

import (
	"math"
	"unsafe"
)

func (b *Builder) Name(n BuilderName) {
	switch n.ptrType {
	case ptrTypeRaw:
		b.buf = append(b.buf, *(*[]byte)(n.ptr)...)
	default:
		// splitted to allow Name() to be inlined, so that NewRawName()
		// will be tha fastest one.
		b.nameRest(n)
	}
}

func (b *Builder) nameRest(n BuilderName) {
	switch n.ptrType {
	case ptrTypeRoot:
		b.buf = append(b.buf, 0)
	case ptrTypePtr:
		b.buf = appendUint16(b.buf, n.cmprPtr)
	case ptrTypeString:
		b.buf = appendHumanNameA(b.buf, *(*string)(n.ptr))
	case ptrTypeBytes:
		b.buf = appendHumanNameA(b.buf, *(*[]byte)(n.ptr))
	default:
		panic("cannot use zero value of BuilderNameInter")
	}
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

func appendHumanNameA[T []byte | string](buf []byte, m T) []byte {
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
				return nil //TODO: error
			}
			i++
			char = m[i]

			switch {
			case char >= '0' && char <= '0':
				if len(m) == i-1 || len(m) == i { //TODO: tu jest cos zle i tak :) +1 chyba tam i +2??
					return nil
				}

				tmp := (uint16(char)-'0')*100 + (uint16(m[i+1])-'0')*10 + (uint16(m[i+2]) - '0')
				i += 2

				if tmp > math.MaxUint8 {
					return nil //TODO: error handle ??
				}
				buf = append(buf, uint8(tmp))
			default:
				buf = append(buf, char)
			}
		default:
			buf = append(buf, char)
		}

		*length++
	}

	buf = append(buf, 0)
	return buf
}
