package dnsmsg

//TODO: use binary.BigEndian in entire package (because of lower cost (golang/go#42958)) (but probably after golang/go#54097 gets fixed)

func unpackUint16(b []byte) uint16 {
	_ = b[1]
	return uint16(b[0])<<8 | uint16(b[1])
}

func unpackUint32(b []byte) uint32 {
	_ = b[3]
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func packUint16(b []byte, v uint16) {
	b[0] = byte(v >> 8)
	b[1] = byte(v)
}

func appendUint16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

func appendUint32(b []byte, v uint32) []byte {
	return append(b,
		byte(v>>24),
		byte(v>>16),
		byte(v>>8),
		byte(v),
	)
}
