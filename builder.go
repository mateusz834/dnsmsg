package dnsmsg

import "sync"

func MakeQuery(msg []byte, id uint16, flags Flags, q Question[*BuilderName]) ([]byte, error) {
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

func MakeQueryWithEDNS0(msg []byte, id uint16, flags Flags, q Question[*BuilderName], ends0 EDNS0) ([]byte, error) {
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

type EDNS0 struct {
	Payload uint16
}

type Builder struct {
	m   map[string]uint16
	buf []byte

	oneSameName     bool
	firstNameOffset uint16
	firstNameEnd    uint16
}

func NewBuilder(buf []byte) Builder {
	return Builder{
		buf: buf,
	}
}

func (b *Builder) Finish() (msg []byte) {
	putMap(b.m)
	msg = b.buf
	*b = Builder{}
	return msg
}

var maps = sync.Pool{
	New: func() any {
		return map[string]uint16{}
	},
}

func getMap() map[string]uint16 {
	return maps.Get().(map[string]uint16)
}

func putMap(m map[string]uint16) {
	if m != nil {
		for i := range m {
			delete(m, i)
		}
		maps.Put(m)
	}
}
