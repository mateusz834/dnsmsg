package dnsmsg

type Type uint16

const (
	TypeA Type = 1
)

type Class uint16

const (
	ClassIN Class = 1
)

type Header struct {
	ID      uint16
	Flags   Flags
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

const headerLen = 12

func (h *Header) unpack(msg []byte) (uint16, error) {
	if len(msg) < headerLen {
		return 0, errInvalidDNSMessage
	}

	h.ID = unpackUint16(msg[:2])
	h.Flags = Flags(unpackUint16(msg[2:4]))
	h.QDCount = unpackUint16(msg[4:6])
	h.ANCount = unpackUint16(msg[6:8])
	h.NSCount = unpackUint16(msg[8:10])
	h.ARCount = unpackUint16(msg[10:12])

	return headerLen, nil
}

type nameConstraint interface {
	ParserName | BuilderName
}

type Question[T nameConstraint] struct {
	Name  T
	Type  Type
	Class Class
}

type ResourceHeader[T nameConstraint] struct {
	Name   T
	Type   Type
	Class  Class
	TTL    uint32
	Length uint16
}

type ResourceA struct {
	A [4]byte
}

type ResourceAAAA struct {
	AAAA [16]byte
}

type ResourceCNAME[T nameConstraint] struct {
	CNAME T
}

type ResourceMX[T nameConstraint] struct {
	MX   T
	Pref uint16
}

type ResourceTXT struct {
	// TXT is as defined by RFC 1035 a "One or more <character-string>s"
	// so it is a one or more byte-length prefixed data
	TXT []byte
}

type ResourceSOA[T nameConstraint] struct {
	NS      T
	Mbox    T
	Setial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Minimum uint32
}
