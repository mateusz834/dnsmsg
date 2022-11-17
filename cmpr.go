package dnsmsg

func MakeQuery(msg []byte, id uint16, flags Flags, q Question[*CmprBuilderName]) ([]byte, error) {
	// Header
	msg = appendUint16(msg, id)
	msg = appendUint16(msg, uint16(flags))
	msg = appendUint16(msg, 1)
	msg = appendUint16(msg, 0)
	msg = appendUint16(msg, 0)
	msg = appendUint16(msg, 0)

	// Question
	var err error
	msg, err = appendName(msg, q.Name)
	if err != nil {
		return nil, err
	}

	msg = appendUint16(msg, uint16(q.Type))
	msg = appendUint16(msg, uint16(q.Class))
	return msg, nil
}

func MakeQueryWithEDNS0(msg []byte, id uint16, flags Flags, q Question[*CmprBuilderName], ends0 EDNS0) ([]byte, error) {
	// Header
	msg = appendUint16(msg, id)
	msg = appendUint16(msg, uint16(flags))
	msg = appendUint16(msg, 1)
	msg = appendUint16(msg, 0)
	msg = appendUint16(msg, 0)
	msg = appendUint16(msg, 1)

	// Question
	var err error
	msg, err = appendName(msg, q.Name)
	if err != nil {
		return nil, err
	}

	msg = appendUint16(msg, uint16(q.Type))
	msg = appendUint16(msg, uint16(q.Class))

	// EDNS0
	msg = append(msg, 0) // root name
	msg = appendUint16(msg, uint16(TypeOPT))
	msg = appendUint16(msg, ends0.Payload)

	// TODO: support rest of EDNS0 stuff.
	msg = appendUint32(msg, 0)
	msg = appendUint16(msg, 0)
	return msg, nil
}

func appendName(buf []byte, name *CmprBuilderName) ([]byte, error) {
	switch name := name.val.(type) {
	case rawName:
		buf = append(buf, name...)
		return buf, nil
	case string:
		var err error
		buf, _, err = appendHumanName(buf, name, maxNameLen, true)
		return buf, err
	case []byte:
		var err error
		buf, _, err = appendHumanName(buf, name, maxNameLen, true)
		return buf, err
	default:
		panic("aa TODO")
	}
}

type EDNS0 struct {
	Payload uint16
}

type CmprBuilder struct {
	m   map[string]uint16
	buf []byte

	oneSameName     bool
	firstNameOffset uint16
}

// BuilderName should be used only within the same builder, reusing them
// between different builder might cause a unexpected behaviour.
type CmprBuilderName struct {
	val   any
	inMsg bool
}

func NewCmprStringName(name string) *CmprBuilderName {
	return &CmprBuilderName{val: name}
}

func NewCmprBytesName(name []byte) *CmprBuilderName {
	return &CmprBuilderName{val: name}
}

func NewCmprRawName(name []byte) *CmprBuilderName {
	return &CmprBuilderName{val: rawName(name)}
}

func NewCmprBuilder(buf []byte) CmprBuilder {
	return CmprBuilder{
		buf: buf,
	}
}

func (b *CmprBuilder) Finish() []byte {
	return b.buf
}

// Name appends the name to the message.
func (b *CmprBuilder) Name(n *CmprBuilderName) error {
	// This implementation is done in such way not to use the b.m map
	// while building messages with the same name.

	if b.oneSameName && b.m == nil {
		if n.inMsg {
			b.buf = appendUint16(b.buf, 0xC000|b.firstNameOffset)
			return nil
		}

		// We got different name, allocate hash map and populate it
		b.m = make(map[string]uint16)
		rawNameStr := string(b.buf[b.firstNameOffset:])
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

		switch name := n.val.(type) {
		case rawName:
			b.buf = append(b.buf, name...)
			return nil
		case string:
			var err error
			b.buf, _, err = appendHumanName(b.buf, name, maxNameLen, true)
			return err
		case []byte:
			var err error
			b.buf, _, err = appendHumanName(b.buf, name, maxNameLen, true)
			return err
		}
	}

	var raw string

	switch name := n.val.(type) {
	case rawName:
		raw = string(name)
	case string:
		r, _, err := appendHumanName(make([]byte, 0, len(name)), name, maxNameLen, true)
		if err != nil {
			return err
		}
		raw = string(r)
	case []byte:
		r, _, err := appendHumanName(make([]byte, 0, len(name)), name, maxNameLen, true)
		if err != nil {
			return err
		}
		raw = string(r)
	default:
		panic("cannot use zero value of BuilderName")
	}

	for i := 0; i < len(raw) && raw[i] != 0; i += int(raw[i]) + 1 {
		ptr, ok := b.m[string(raw[i:])]
		if ok {
			b.buf = append(b.buf, raw[:i]...)
			b.buf = appendUint16(b.buf, 0xC000|ptr)
			return nil
		}
		b.m[string(raw[i:])] = b.firstNameOffset + uint16(i)
	}

	b.buf = append(b.buf, raw...)
	return nil
}

func equalRaw(msg []byte, im1 uint16, raw []byte) bool {
	im2 := uint16(0)

	for {
		// Resolve all (in a row) compression pointers of m
		for msg[im1]&0xC0 == 0xC0 {
			im1 = uint16(msg[im1]^0xC0)<<8 | uint16(msg[im1+1])
		}

		if len(raw) <= int(im2) {
			return false
		}

		// different label lengths
		if msg[im1] != raw[im2] {
			return false
		}

		if msg[im1] == 0 {
			return true
		}

		if uint16(len(raw[im2:])) < uint16(raw[im2])+1 {
			return false
		}

		if !equal(msg[im1+1:im1+1+uint16(msg[im1])], raw[im2+1:im2+1+uint16(raw[im2])]) {
			return false
		}

		im1 += uint16(msg[im1]) + 1
		im2 += uint16(raw[im2]) + 1
	}
}
