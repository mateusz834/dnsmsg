package dnsmsg

func appendUint16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

type Builder struct {
	buf []byte
}

func NewBuilder(buf []byte) Builder {
	return Builder{
		buf: buf,
	}
}

func (b *Builder) Finish() (msg []byte) {
	msg = b.buf
	b.buf = nil
	return msg
}
