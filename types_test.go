package dnsmsg

import (
	"testing"
)

var testFlags = []struct {
	name  string
	flags Flags

	expectFlags    Flags
	expectRCode    RCode
	expectOpCode   OpCode
	expectResponse bool
	expectBits     []Bit
}{
	{
		name: "set AA bit",
		flags: func() (f Flags) {
			f.SetBit(BitAA, true)
			return f
		}(),
		expectFlags: Flags(0b00000100_00000000),
		expectBits:  []Bit{BitAA},
	},

	{
		name: "set TC bit",
		flags: func() (f Flags) {
			f.SetBit(BitTC, true)
			return f
		}(),
		expectFlags: Flags(0b00000010_00000000),
		expectBits:  []Bit{BitTC},
	},

	{
		name: "set RD bit",
		flags: func() (f Flags) {
			f.SetBit(BitRD, true)
			return f
		}(),
		expectFlags: Flags(0b00000001_00000000),
		expectBits:  []Bit{BitRD},
	},

	{
		name: "set RA bit",
		flags: func() (f Flags) {
			f.SetBit(BitRA, true)
			return f
		}(),
		expectFlags: Flags(0b00000000_10000000),
		expectBits:  []Bit{BitRA},
	},

	{
		name: "set reserved bit (1 << 6)",
		flags: func() (f Flags) {
			f.SetBit(Bit(6), true)
			return f
		}(),
		expectFlags: Flags(0b00000000_01000000),
		expectBits:  []Bit{Bit(6)},
	},

	{
		name: "set AD bit",
		flags: func() (f Flags) {
			f.SetBit(BitAD, true)
			return f
		}(),
		expectFlags: Flags(0b00000000_00100000),
		expectBits:  []Bit{BitAD},
	},

	{
		name: "set CD bit",
		flags: func() (f Flags) {
			f.SetBit(BitCD, true)
			return f
		}(),
		expectFlags: Flags(0b00000000_00010000),
		expectBits:  []Bit{BitCD},
	},

	{
		name: "set AA, set CD to true, then to false",
		flags: func() (f Flags) {
			f.SetBit(BitAA, true)
			f.SetBit(BitCD, true)
			f.SetBit(BitCD, false)
			return f
		}(),
		expectFlags: Flags(0b00000100_00000000),
		expectBits:  []Bit{BitAA},
	},

	{
		name: "set AA, set CD to true, then false, then true",
		flags: func() (f Flags) {
			f.SetBit(BitAA, true)
			f.SetBit(BitCD, true)
			f.SetBit(BitCD, false)
			f.SetBit(BitCD, true)
			return f
		}(),
		expectFlags: Flags(0b00000100_00010000),
		expectBits:  []Bit{BitAA, BitCD},
	},

	{
		name: "set RCode to 0b1111",
		flags: func() (f Flags) {
			f.SetRCode(RCode(0b1111))
			return f
		}(),
		expectFlags: Flags(0b00000000_00001111),
		expectRCode: RCode(0b1111),
	},
	{
		name: "set RCode to 0b1001",
		flags: func() (f Flags) {
			f.SetRCode(RCode(0b1001))
			return f
		}(),
		expectFlags: Flags(0b00000000_00001001),
		expectRCode: RCode(0b1001),
	},
	{
		name: "set Response, set RCode to 0b1001, then change it to 0b1100",
		flags: func() (f Flags) {
			f.SetResponse()
			f.SetRCode(RCode(0b1001))
			f.SetRCode(RCode(0b1100))
			return f
		}(),
		expectFlags:    Flags(0b10000000_00001100),
		expectRCode:    RCode(0b1100),
		expectResponse: true,
	},

	{
		name: "set OpCode to 0b1111",
		flags: func() (f Flags) {
			f.SetOpCode(OpCode(0b1111))
			return f
		}(),
		expectFlags:  Flags(0b01111000_00000000),
		expectOpCode: OpCode(0b1111),
	},
	{
		name: "set OpCode to 0b1001",
		flags: func() (f Flags) {
			f.SetOpCode(OpCode(0b1001))
			return f
		}(),
		expectFlags:  Flags(0b01001000_00000000),
		expectOpCode: OpCode(0b1001),
	},
	{
		name: "set Response, set OpCode to 0b1001, then change it to 0b1100",
		flags: func() (f Flags) {
			f.SetResponse()
			f.SetOpCode(OpCode(0b1001))
			f.SetOpCode(OpCode(0b1100))
			return f
		}(),
		expectFlags:    Flags(0b11100000_00000000),
		expectOpCode:   OpCode(0b1100),
		expectResponse: true,
	},

	{
		name: "set Response, then set Query",
		flags: func() (f Flags) {
			f.SetResponse()
			f.SetQuery()
			return f
		}(),
	},
}

func TestFlags(t *testing.T) {
	for i, v := range testFlags {
		if v.expectFlags != v.flags {
			t.Errorf("%v: %v: expected Flags: %016b, got: %016b", i, v.name, v.expectFlags, v.flags)
			continue
		}

		if rCode := v.flags.RCode(); v.expectRCode != rCode {
			t.Errorf("%v: %v: expected RCode: %v, got: %v", i, v.name, v.expectRCode, rCode)
		}

		if opCode := v.flags.OpCode(); v.expectOpCode != opCode {
			t.Errorf("%v: %v: expected RCode: %v, got: %v", i, v.name, v.expectRCode, opCode)
		}

		if response := v.flags.Response(); v.expectResponse != response {
			t.Errorf("%v: %v: expected response: %v, got: %v", i, v.name, v.expectResponse, response)
		}

		if v.flags.Response() == v.flags.Query() {
			t.Errorf("%v: %v: both response and query bit set or unset", i, v.name)
		}

		bitSet := map[Bit]struct{}{}

		for _, bit := range v.expectBits {
			bitSet[bit] = struct{}{}

			if !v.flags.Bit(bit) {
				t.Errorf("%v: %v: bit: %v is not set", i, v.name, bit)
			}
		}

		for bit := Bit(BitCD); bit <= BitAA; bit++ {
			if _, ok := bitSet[bit]; ok {
				continue
			}

			if v.flags.Bit(bit) {
				t.Errorf("%v: %v: bit: %v is set", i, v.name, bit)
			}
		}
	}
}
