package dnsmsg

const (
	defaultQueryFlags Flags = bitRD
)

const (
	bitQR = 1 << 15

	bitAA = 1 << 10
	bitTC = 1 << 9
	bitRD = 1 << 8
	bitRA = 1 << 7
	bitAD = 1 << 5
	bitCD = 1 << 4
)

type Flags uint16

func (f Flags) Query() bool {
	return f&bitQR == 0
}

func (f Flags) Response() bool {
	return f&bitQR != 0
}

/*
func (f Flags) Opcode() uint8 {
	return uint8(f & 0x7800)
}
*/

func (f Flags) BitAA() bool {
	return f&bitAA != 0
}

func (f Flags) BitTC() bool {
	return f&bitTC != 0
}

func (f Flags) BitRD() bool {
	return f&bitRD != 0
}

func (f Flags) BitRA() bool {
	return f&bitRA != 0
}

func (f Flags) BitAD() bool {
	return f&bitAD != 0
}

func (f Flags) BitCD() bool {
	return f&bitCD != 0
}

func (f *Flags) SetRD() {
	*f |= bitRD
}

/*
func (f Flags) RCode() RCode {
	return RCode(f & 0xF)
}
*/
