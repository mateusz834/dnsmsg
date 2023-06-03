package dnsmsg

import (
	"strconv"
	"strings"
)

type EDNS0 struct {
	Payload uint16
}

type name interface {
	ParserName | Name
}

type Type uint16

func (t Type) String() string {
	switch t {
	case TypeA:
		return "A"
	case TypeNS:
		return "NS"
	case TypeCNAME:
		return "CNAME"
	case TypeSOA:
		return "SOA"
	case TypePTR:
		return "PTR"
	case TypeMX:
		return "MX"
	case TypeTXT:
		return "TXT"
	case TypeAAAA:
		return "AAAA"
	case TypeOPT:
		return "OPT"
	default:
		return "0x" + strconv.FormatInt(int64(t), 16)
	}
}

const (
	TypeA     Type = 1
	TypeNS    Type = 2
	TypeCNAME Type = 5
	TypeSOA   Type = 6
	TypePTR   Type = 12
	TypeMX    Type = 15
	TypeTXT   Type = 16
	TypeAAAA  Type = 28
	TypeOPT   Type = 41
)

type Class uint16

func (t Class) String() string {
	switch t {
	case ClassIN:
		return "IN"
	default:
		return "0x" + strconv.FormatInt(int64(t), 16)
	}
}

const (
	ClassIN Class = 1
)

type Bit uint8

const (
	BitAA Bit = 10
	BitTC Bit = 9
	BitRD Bit = 8
	BitRA Bit = 7
	BitAD Bit = 5
	BitCD Bit = 4
)

type OpCode uint8

const (
	OpCodeQuery OpCode = 0
)

type RCode uint8

func (r RCode) String() string {
	switch r {
	case RCodeSuccess:
		return "success"
	case RCodeFormatError:
		return "format erro"
	case RCodeServerFail:
		return "server failure"
	case RCodeNameError:
		return "name error"
	case RCodeNotImpl:
		return "not implemented"
	case RCodeRefused:
		return "refused"
	default:
		return "0x" + strconv.FormatInt(int64(r), 16)
	}
}

const (
	RCodeSuccess RCode = iota
	RCodeFormatError
	RCodeServerFail
	RCodeNameError
	RCodeNotImpl
	RCodeRefused
)

type Flags uint16

const bitQR = 1 << 15

func (f Flags) Query() bool {
	return f&bitQR == 0
}

func (f Flags) Response() bool {
	return f&bitQR != 0
}

func (f Flags) Bit(bit Bit) bool {
	return f&(1<<bit) != 0
}

func (f Flags) OpCode() OpCode {
	return OpCode((f >> 11) & 0b1111)
}

func (f Flags) RCode() RCode {
	return RCode(f & 0b1111)
}

func (f *Flags) SetQuery() {
	*f &= ^Flags(bitQR) // zero the QR bit
}

func (f *Flags) SetResponse() {
	*f |= bitQR
}

func (f *Flags) SetBit(bit Bit, val bool) {
	*f &= ^Flags(1 << bit) // zero bit
	if !val {
		return
	}
	*f |= (1 << bit)
}

func (f *Flags) SetOpCode(o OpCode) {
	*f &= ^Flags(0b1111 << 11) // zero the opcode bits
	*f |= Flags(o) << 11
}

func (f *Flags) SetRCode(r RCode) {
	*f &= ^Flags(0b1111) // zero the rcode bits
	*f |= Flags(r)
}

const headerLen = 12

type Header struct {
	ID      uint16
	Flags   Flags
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

func (h *Header) unpack(msg [headerLen]byte) {
	h.ID = unpackUint16(msg[:2])
	h.Flags = Flags(unpackUint16(msg[2:4]))
	h.QDCount = unpackUint16(msg[4:6])
	h.ANCount = unpackUint16(msg[6:8])
	h.NSCount = unpackUint16(msg[8:10])
	h.ARCount = unpackUint16(msg[10:12])
}

type Question[T name] struct {
	Name  T
	Type  Type
	Class Class
}

type ResourceHeader[T name] struct {
	Name   T
	Type   Type
	Class  Class
	TTL    uint32
	Length uint16
}

type ResourceA struct {
	A [4]byte
}

type ResourceNS[T name] struct {
	NS T
}

type ResourceCNAME[T name] struct {
	CNAME T
}

type ResourceSOA[T name] struct {
	NS      T
	Mbox    T
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Minimum uint32
}

type ResourcePTR[T name] struct {
	PTR T
}

type ResourceMX[T name] struct {
	MX   T
	Pref uint16
}

type ResourceTXT struct {
	// TXT is as defined by RFC 1035 a "One or more <character-string>s"
	// so it is a one or more byte-length prefixed data
	TXT []byte
}

func (r ResourceTXT) concatLength() int {
	length := 0
	for i := 0; i < len(r.TXT); i += int(r.TXT[i]) + 1 {
		length += len(r.TXT[i : i+int(r.TXT[i])])
	}
	return length
}

func (r ResourceTXT) Concat() []byte {
	buf := make([]byte, 0, r.concatLength())
	for i := 0; i < len(r.TXT); i += int(r.TXT[i]) + 1 {
		buf = append(buf, r.TXT[i:i+int(r.TXT[i])]...)
	}
	return buf
}

func (r ResourceTXT) String() string {
	var b strings.Builder
	b.Grow(r.concatLength())
	for i := 0; i < len(r.TXT); i += int(r.TXT[i]) + 1 {
		b.Write(r.TXT[i : i+int(r.TXT[i])])
	}
	return b.String()
}

type ResourceAAAA struct {
	AAAA [16]byte
}
