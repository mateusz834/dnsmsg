package dnsmsg

import (
	"errors"
	"math"
)

/*

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

/*
func (b *Builder) Name(n *BuilderName) (err error) {
	n.msgOffset = uint16(len(b.buf))

	switch n.ptrType {
	case ptrTypeRoot:
		b.buf = append(b.buf, 0)
	case ptrTypePtr:
		b.buf = appendUint16(b.buf, n.cmprPtr)

	case ptrTypeRaw:
		b.buf = append(b.buf, *(*[]byte)(n.ptr)...)
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
*/

//TODO: zamiast addOff można dodać skipLabelCount teź

/*
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
*/

type rootName struct{}

type ptrName uint16
type ptrToName *BuilderName

type rawName []byte
type rawNameWithPtr struct {
	prefix []byte
	ptr    uint16
}
type rawNameWithPtrTo struct {
	to     *BuilderName
	prefix []byte
}

type stringName string
type stringNameWithPtr struct {
	prefix string
	ptr    uint16
}
type stringNameWithPtrTo struct {
	to     *BuilderName
	prefix string
}

type bytesName []byte
type bytesNameWithPtr struct {
	prefix []byte
	ptr    uint16
}
type bytesNameWithPtrTo struct {
	to     *BuilderName
	prefix []byte
}

type BuilderName struct {
	val   any
	inMsg bool

	// inMsgLen conains the length of the encoded Name
	// When val is a PtrTo name type, then it is a sum
	// of the lengths.
	inMsgLen  uint8
	msgOffset uint16
}

func NewRawName(raw []byte) BuilderName {
	return BuilderName{
		val: rawName(raw),
	}
}

func NewRawNameWithPtr(raw []byte, ptr uint16) BuilderName {
	return BuilderName{
		val: rawNameWithPtr{
			prefix: raw,
			ptr:    ptr | 0xC000,
		},
	}
}

func NewRawNameWithPtrTo(raw []byte, to *BuilderName) BuilderName {
	return BuilderName{
		val: rawNameWithPtrTo{
			prefix: raw,
			to:     to,
		},
	}
}

func NewStringName(name string) BuilderName {
	return BuilderName{
		val: stringName(name),
	}
}

func NewStringNameWithPtr(name string, ptr uint16) BuilderName {
	return BuilderName{
		val: stringNameWithPtr{
			prefix: name,
			ptr:    ptr | 0xC000,
		},
	}
}

func NewStringNameWithPtrTo(name string, ptrTo *BuilderName) BuilderName {
	return BuilderName{
		val: stringNameWithPtrTo{
			prefix: name,
			to:     ptrTo,
		},
	}
}

func NewBytesName(name []byte) BuilderName {
	return BuilderName{
		val: bytesName(name),
	}
}

func NewBytesNameWithPtr(name []byte, ptr uint16) BuilderName {
	return BuilderName{
		val: bytesNameWithPtr{
			prefix: name,
			ptr:    ptr | 0xC000,
		},
	}
}

func NewBytesNameWithPtrTo(name []byte, ptrTo *BuilderName) BuilderName {
	return BuilderName{
		val: bytesNameWithPtrTo{
			prefix: name,
			to:     ptrTo,
		},
	}
}

func NewRootName() BuilderName {
	return BuilderName{
		val: rootName{},
	}
}

func NewPtrName(ptr uint16) BuilderName {
	return BuilderName{
		val: ptrName(ptr | 0xC000),
	}
}

func (b *Builder) Name(n *BuilderName) (err error) {
	msgOffset := uint16(math.MaxUint16)
	if len(b.buf) <= int(^uint16(0xC000)) {
		msgOffset = uint16(len(b.buf))
	}

	switch v := n.val.(type) {
	case rootName:
		b.buf = append(b.buf, 0)
	case ptrName:
		b.buf = appendUint16(b.buf, uint16(v))
	case ptrToName:
		if !v.inMsg || v.msgOffset == math.MaxUint16 {
			return errors.New("xd")
		}
		b.buf = appendUint16(b.buf, v.msgOffset|0xC000)
	case rawName:
		b.buf = append(b.buf, v...)
	case rawNameWithPtr:
		b.buf = append(b.buf, v.prefix...)
		b.buf = appendUint16(b.buf, v.ptr)
	case rawNameWithPtrTo:
		// TODO: in this case, just put the name as is ??
		// TODO: only in the second case == math.MaxUint16
		if !v.to.inMsg || v.to.msgOffset == math.MaxUint16 {
			return errors.New("xd")
		}
		b.buf = append(b.buf, v.prefix...)
		b.buf = appendUint16(b.buf, v.to.msgOffset|0xC000)

	case stringName:
		b.buf, n.inMsgLen, err = appendHumanName(b.buf, string(v), maxNameLen, true)
	case stringNameWithPtr:
		b.buf, _, err = appendHumanName(b.buf, v.prefix, maxNameLen, true)
		if err != nil {
			return err
		}
		b.buf = b.buf[:len(b.buf)-1] // remove root
		b.buf = appendUint16(b.buf, v.ptr)
	case stringNameWithPtrTo:
		if !v.to.inMsg {
			return errors.New("xd")
		}

		// We can't point to the name directly using compression pointer,
		// we are not going to fit in 14 bits. So write the entire name here,
		// without compression pointers.
		if v.to.msgOffset == math.MaxUint16 {
			b.buf, n.inMsgLen, err = appendHumanName(b.buf, v.prefix, maxNameLen, false)
			if err != nil {
				return err
			}

			availLen := maxNameLen - n.inMsgLen
			if v.to.inMsgLen > availLen {
				return errInvalidDNSName
			}

			return b.Name(&BuilderName{val: v.to.val})
		}

		var length uint8
		b.buf, length, err = appendHumanName(b.buf, v.prefix, maxNameLen-v.to.inMsgLen, false)
		if err != nil {
			return err
		}
		n.inMsgLen += length
		b.buf = appendUint16(b.buf, v.to.msgOffset|0xC000)

	case bytesName:
		b.buf, _, err = appendHumanName(b.buf, []byte(v), maxNameLen, true)
	case bytesNameWithPtr:
		b.buf, _, err = appendHumanName(b.buf, v.prefix, maxNameLen, true)
		if err != nil {
			return err
		}
		b.buf = b.buf[:len(b.buf)-1] // remove root
		b.buf = appendUint16(b.buf, v.ptr)
	case bytesNameWithPtrTo:
		if !v.to.inMsg || v.to.msgOffset == math.MaxUint16 {
			return errors.New("xd")
		}

		b.buf, _, err = appendHumanName(b.buf, v.prefix, maxNameLen, true)
		if err != nil {
			return err
		}
		b.buf = b.buf[:len(b.buf)-1] // remove root
		b.buf = appendUint16(b.buf, v.to.msgOffset|0xC000)

	default:
		panic("u")
	}

	n.msgOffset = msgOffset
	n.inMsg = true
	return err
}

const maxNameLen = 255

func appendHumanName[T []byte | string](buf []byte, m T, maxNameLen uint8, endRoot bool) ([]byte, uint8, error) {
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
				return nil, 0, errInvalidDNSName
			}
			i++
			char = m[i]

			if char >= '0' && char <= '9' {
				if len(m) == i+1 || len(m) == i+2 {
					return nil, 0, errInvalidDNSName
				}

				if !(m[i+1] >= '0' && m[i+1] <= '9' && m[i+2] >= '0' && m[i+2] <= '9') {
					return nil, 0, errInvalidDNSName
				}

				tmp := (uint16(char)-'0')*100 + (uint16(m[i+1])-'0')*10 + (uint16(m[i+2]) - '0')
				i += 2

				if tmp > math.MaxUint8 {
					return nil, 0, errInvalidDNSName
				}
				char = uint8(tmp)
			}
		}
		buf = append(buf, char)
		*length++
		if *length > 63 {
			return nil, 0, errInvalidDNSName
		}
	}

	if endRoot {
		buf = append(buf, 0)
	}

	if len(buf)-startLen > int(maxNameLen) {
		return nil, 0, errInvalidDNSName
	}
	return buf, uint8(len(buf) - startLen), nil
}
