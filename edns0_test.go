package dnsmsg

import (
	"bytes"
	"fmt"
	"testing"
)

func TestEDNS0Header(t *testing.T) {
	rCode := RCode(0b0110)
	extRCode := ExtendedRCode(0b11010111_0110)

	edns0Hdr := EDNS0Header{
		PartialExtendedRCode: extRCode.PartialExtendedRCode(),
		Version:              0b11001010,
		ExtendedFlags:        0b1111010011011011,
		Payload:              0b1010110111001110,
	}

	edns0ResHdr := edns0Hdr.AsResourceHeader()
	if edns0ResHdr.Class != 0b1010110111001110 {
		t.Fatalf("edns0ResHdr.Class = %b, want %b", edns0ResHdr.Class, 0b1010110111001110)
	}
	if edns0ResHdr.TTL != 0b11010111_11001010_1111010011011011 {
		t.Fatalf("edns0ResHdr.Class = %b, want %b", edns0ResHdr.Class, 0b10101101_11001010_1111010011011011)
	}

	edns0Hdr2, err := edns0ResHdr.AsEDNS0Header()
	if err != nil {
		t.Fatalf("%#v.AsResourceHeader().AsEDNS0Header() unexpected error: %v", edns0Hdr, err)
	}
	if edns0Hdr != edns0Hdr2 {
		t.Fatalf("%#v.AsResourceHeader().AsEDNS0Header() = %#v, want: %#v", edns0Hdr, edns0Hdr2, edns0Hdr)
	}
	extRCode2 := NewExtendedRCode(edns0Hdr2.PartialExtendedRCode, rCode)
	if extRCode != extRCode2 {
		t.Fatalf("NewExtendedRCode(%#v.AsResourceHeader().AsEDNS0Header().PartialExtendedRCode, rCode) = %#v, want: %#v", edns0Hdr, extRCode2, extRCode)
	}

	b := StartBuilder(make([]byte, 0, 512), 0, 0)
	b.StartAnswers()
	b.StartAuthorities()
	b.StartAdditionals()
	if err = b.ResourceOPT(edns0ResHdr, ResourceOPT{}); err != nil {
		t.Fatalf("b.ResourceOPT(%#v, %#v) unexpected error: %v", edns0ResHdr, ResourceOPT{}, err)
	}

	p, _, err := Parse(b.Bytes())
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if err = p.StartAnswers(); err != nil {
		t.Fatalf("p.StartAnswers() unexpected error: %v", err)
	}
	if err = p.StartAuthorities(); err != nil {
		t.Fatalf("p.StartAuthorities() unexpected error: %v", err)
	}
	if err = p.StartAdditionals(); err != nil {
		t.Fatalf("p.StartAdditionals() unexpected error: %v", err)
	}

	pResHdr, err := p.ResourceHeader()
	if err != nil {
		t.Fatalf("p.ResourceHeader() unexpected error: %v", err)
	}
	edns0Hdr3, err := pResHdr.AsEDNS0Header()
	if err != nil {
		t.Fatalf("p.ResourceHeader().AsEDNS0Header() unexpected error: %v", err)
	}

	if edns0Hdr != edns0Hdr3 {
		t.Fatalf("p.ResourceHeader().AsEDNS0Header() = %#v, want: %#v", edns0Hdr3, edns0Hdr)
	}
	extRCode3 := NewExtendedRCode(edns0Hdr2.PartialExtendedRCode, rCode)
	if extRCode != extRCode3 {
		t.Fatalf("NewExtendedRCode(p.ResourceHeader().AsEDNS0Header().PartialExtendedRCode, rCode) = %#v, want: %#v", extRCode3, extRCode)
	}

	b.Reset(b.Bytes()[:0], 0, 0)
	b.StartAnswers()
	b.StartAuthorities()
	b.StartAdditionals()
	rdb, err := b.RDBuilder(ResourceHeader{
		Name: MustParseName("example.com"),
		Type: TypeOPT,
	})
	if err != nil {
		t.Fatalf("b.RDBuilder() unexpected error: %v", err)
	}
	rdb.End()

	p, _, err = Parse(b.Bytes())
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if err = p.StartAnswers(); err != nil {
		t.Fatalf("p.StartAnswers() unexpected error: %v", err)
	}
	if err = p.StartAuthorities(); err != nil {
		t.Fatalf("p.StartAuthorities() unexpected error: %v", err)
	}
	if err = p.StartAdditionals(); err != nil {
		t.Fatalf("p.StartAdditionals() unexpected error: %v", err)
	}

	pResHdr, err = p.ResourceHeader()
	if err != nil {
		t.Fatalf("p.ResourceHeader() unexpected error: %v", err)
	}
	if _, err = pResHdr.AsEDNS0Header(); err != errInvalidEDNS0Header {
		t.Fatalf("p.ResourceHeader().AsEDNS0Header() unexpected error: %v, want %v", err, errInvalidEDNS0Header)
	}

	edns0ResHdr.Name = MustParseName("example.com")
	if _, err = edns0ResHdr.AsEDNS0Header(); err != errInvalidEDNS0Header {
		t.Fatalf("%#v.AsEDNS0Header() unexpected error: %v, want: %v", edns0ResHdr, err, errInvalidEDNS0Header)
	}
}

func TestResourceOPTBuilderAndParser(t *testing.T) {
	expectPanic := func(name string, f func()) {
		defer func() {
			if recover() == nil {
				t.Fatalf("%v: didn't panic", name)
			}
		}()
		f()
	}

	b := StartBuilder(make([]byte, 0, 512), 0, 0)
	b.StartAnswers()
	b.StartAuthorities()
	b.StartAdditionals()

	optsb1, err := b.ResourceOPTBuilder(EDNS0Header{
		Payload:              1111,
		PartialExtendedRCode: 0,
		Version:              0,
		ExtendedFlags:        0,
	}.AsResourceHeader())
	if err != nil {
		t.Fatalf("b.ResourceOPTBuilder() unexpected error: %v", err)
	}
	optb3, err := optsb1.OptionBuilder(0)
	if err != nil {
		t.Fatalf("optsb1.OptionBuilder(0) unexpected error: %v", err)
	}

	expectPanic("b.ResourceA()", func() {
		b.ResourceA(ResourceHeader{
			Name: MustParseName("example.com"),
		}, ResourceA{A: [4]byte{192, 0, 2, 1}})
	})

	expectPanic("opts1.ClientSubnet()", func() {
		optsb1.ClientSubnet(EDNS0ClientSubnet{
			Family:             AddressFamilyIPv4,
			SourcePrefixLength: 8,
			ScopePrefixLength:  7,
			Address:            []byte{192, 0, 2, 1},
		})
	})
	expectPanic("optsb1.Cookie()", func() {
		optsb1.Cookie(EDNS0Cookie{
			ClientCookie:                 [8]byte{1, 2, 34, 31, 184, 122, 222, 111},
			ServerCookie:                 [32]byte{111, 34, 222, 194, 1, 22, 4, 11, 84, 34, 99, 99, 77, 23, 12},
			ServerCookieAdditionalLength: 16,
		})
	})
	expectPanic("optsb1.ExtendedDNSError()", func() {
		optsb1.ExtendedDNSError(EDNS0ExtendedDNSError{
			InfoCode:  1,
			ExtraText: []byte("error text"),
		})
	})
	expectPanic("optsb1.OptionBuilder()", func() {
		optsb1.OptionBuilder(0)
	})

	optb3.Remove()

	err = optsb1.ExtendedDNSError(EDNS0ExtendedDNSError{
		InfoCode:  11,
		ExtraText: []byte("text"),
	})
	if err != nil {
		t.Fatalf("optsb1.ExtendedDNSError() unexpected error: %v", err)
	}
	optsb1.Remove()

	optsb, err := b.ResourceOPTBuilder(EDNS0Header{
		Payload:              1111,
		PartialExtendedRCode: 0,
		Version:              0,
		ExtendedFlags:        0,
	}.AsResourceHeader())
	if err != nil {
		t.Fatalf("b.ResourceOPTBuilder() unexpected error: %v", err)
	}
	if len(b.Bytes()) != 12 || b.Length() != 12 || b.Header() != *new(Header) {
		t.Fatalf("changes caused by ResourceOPTBuilder visible before End()")
	}

	if l := optsb.Length(); l != 0 {
		t.Fatalf("optsb.Length() = %v, want: 0", l)
	}

	expectPanic("b.ResourceA()", func() {
		b.ResourceA(ResourceHeader{
			Name: MustParseName("example.com"),
		}, ResourceA{A: [4]byte{192, 0, 2, 1}})
	})

	if err := optsb.ClientSubnet(EDNS0ClientSubnet{
		Family:             AddressFamilyIPv4,
		SourcePrefixLength: 8,
		ScopePrefixLength:  7,
		Address:            []byte{192, 0, 2, 1},
	}); err != nil {
		t.Fatalf("optsb.ClientSubnet() unexpected error: %v", err)
	}
	if len(b.Bytes()) != 12 || b.Length() != 12 || b.Header() != *new(Header) {
		t.Fatalf("changes caused by ResourceOPTBuilder visible before End()")
	}

	if l := optsb.Length(); l != 11 {
		t.Fatalf("optsb.Length() = %v, want: 11", l)
	}

	if err := optsb.Cookie(EDNS0Cookie{
		ClientCookie:                 [8]byte{1, 2, 34, 31, 184, 122, 222, 111},
		ServerCookie:                 [32]byte{111, 34, 222, 194, 1, 22, 4, 11, 84, 34, 99, 99, 77, 23, 12},
		ServerCookieAdditionalLength: 16,
	}); err != nil {
		t.Fatalf("optsb.Cookie() unexpected error: %v", err)
	}
	if len(b.Bytes()) != 12 || b.Length() != 12 || b.Header() != *new(Header) {
		t.Fatalf("changes caused by ResourceOPTBuilder visible before End()")
	}

	if err := optsb.ExtendedDNSError(EDNS0ExtendedDNSError{
		InfoCode:  1,
		ExtraText: []byte("error text"),
	}); err != nil {
		t.Fatalf("optsb.ExtendedDNSError() unexpected error: %v", err)
	}
	if len(b.Bytes()) != 12 || b.Length() != 12 || b.Header() != *new(Header) {
		t.Fatalf("changes caused by ResourceOPTBuilder visible before End()")
	}
	expectPanic("b.ResourceA()", func() {
		b.ResourceA(ResourceHeader{
			Name: MustParseName("example.com"),
		}, ResourceA{A: [4]byte{192, 0, 2, 1}})
	})

	optb1, err := optsb.OptionBuilder(55000)
	if err != nil {
		t.Fatalf("optsb.OptionBuilder(55000) unexpected error: %v", err)
	}
	if err = optb1.Uint16(8888); err != nil {
		t.Fatalf("optb1.Uint16(8888) unexpected error: %v", err)
	}
	if len(b.Bytes()) != 12 || b.Length() != 12 || b.Header() != *new(Header) {
		t.Fatalf("changes caused by ResourceOPTBuilder visible before End()")
	}
	expectPanic("b.ResourceA()", func() {
		b.ResourceA(ResourceHeader{
			Name: MustParseName("example.com"),
		}, ResourceA{A: [4]byte{192, 0, 2, 1}})
	})
	optb1.Remove()

	beforeOptResourceLength := optsb.Length()

	optb2, err := optsb.OptionBuilder(55001)
	if err != nil {
		t.Fatalf("optsb.OptionBuilder(55001) unexpected error: %v", err)
	}
	if len(b.Bytes()) != 12 || b.Length() != 12 || b.Header() != *new(Header) {
		t.Fatalf("changes caused by ResourceOPTBuilder visible before End()")
	}
	if l := optsb.Length(); l != beforeOptResourceLength {
		t.Fatalf("optsb.Length() = %v, want: %v", l, beforeOptResourceLength)
	}

	expectPanic("b.ResourceA()", func() {
		b.ResourceA(ResourceHeader{
			Name: MustParseName("example.com"),
		}, ResourceA{A: [4]byte{192, 0, 2, 1}})
	})

	expectPanic("optsb.ClientSubnet()", func() {
		optsb.ClientSubnet(EDNS0ClientSubnet{
			Family:             AddressFamilyIPv4,
			SourcePrefixLength: 8,
			ScopePrefixLength:  7,
			Address:            []byte{192, 0, 2, 1},
		})
	})
	expectPanic("optsb.Cookie()", func() {
		optsb.Cookie(EDNS0Cookie{
			ClientCookie:                 [8]byte{1, 2, 34, 31, 184, 122, 222, 111},
			ServerCookie:                 [32]byte{111, 34, 222, 194, 1, 22, 4, 11, 84, 34, 99, 99, 77, 23, 12},
			ServerCookieAdditionalLength: 16,
		})
	})
	expectPanic("optsb.ExtendedDNSError()", func() {
		optsb.ExtendedDNSError(EDNS0ExtendedDNSError{
			InfoCode:  1,
			ExtraText: []byte("error text"),
		})
	})

	if err := optb2.Name(MustParseName("example.com"), false); err != nil {
		t.Fatalf(`optb2.Name(MustNewRawName("example.com") unexpected error: %v`, err)
	}
	if l := optb2.Length(); l != 13 {
		t.Fatalf("optsb.Length() = %v, want: 13", l)
	}
	if len(b.Bytes()) != 12 || b.Length() != 12 || b.Header() != *new(Header) {
		t.Fatalf("changes caused by EDNS0OptionBuilder visible before End()")
	}
	if l := optsb.Length(); l != beforeOptResourceLength {
		t.Fatalf("optsb.Length() = %v, want: %v", l, beforeOptResourceLength)
	}
	if err := optb2.Name(MustParseName("example.com"), true); err != nil {
		t.Fatalf(`optb2.Name(MustNewRawName("example.com", true)) unexpected error: %v`, err)
	}
	if l := optb2.Length(); l != 15 {
		t.Fatalf("optsb.Length() = %v, want: 15", l)
	}
	if err := optb2.Name(MustParseName("www.example.com"), true); err != nil {
		t.Fatalf(`optb2.Name(MustNewRawName("www.example.com", true)) unexpected error: %v`, err)
	}
	if err := optb2.Name(MustParseName("www.example.com"), false); err != nil {
		t.Fatalf(`optb2.Name(MustNewRawName("www.example.com", false)) unexpected error: %v`, err)
	}
	if err := optb2.Uint8(11); err != nil {
		t.Fatalf(`optb2.Uint8(11) unexpected error: %v`, err)
	}
	if err := optb2.Uint16(22111); err != nil {
		t.Fatalf(`optb2.Uint16(22111) unexpected error: %v`, err)
	}
	if err := optb2.Uint32(2283478384); err != nil {
		t.Fatalf(`optb2.Uint32(2283478384) unexpected error: %v`, err)
	}
	if err := optb2.Uint64(9993422834783842); err != nil {
		t.Fatalf(`optb2.Uint32(9993422834783842) unexpected error: %v`, err)
	}
	if err := optb2.Bytes([]byte{1, 2, 3, 4, 5, 6}); err != nil {
		t.Fatalf(`optb2.Bytes([]byte{1, 2, 3, 4, 5, 6}) unexpected error: %v`, err)
	}
	if len(b.Bytes()) != 12 || b.Length() != 12 || b.Header() != *new(Header) {
		t.Fatalf("changes caused by EDNS0OptionBuilder visible before End()")
	}
	if l := optsb.Length(); l != beforeOptResourceLength {
		t.Fatalf("optsb.Length() = %v, want: %v", l, beforeOptResourceLength)
	}
	expectPanic("b.ResourceA()", func() {
		b.ResourceA(ResourceHeader{
			Name: MustParseName("example.com"),
		}, ResourceA{A: [4]byte{192, 0, 2, 1}})
	})
	expectPanic("optsb.ClientSubnet()", func() {
		optsb.ClientSubnet(EDNS0ClientSubnet{
			Family:             AddressFamilyIPv4,
			SourcePrefixLength: 8,
			ScopePrefixLength:  7,
			Address:            []byte{192, 0, 2, 1},
		})
	})
	expectPanic("optsb.Cookie()", func() {
		optsb.Cookie(EDNS0Cookie{
			ClientCookie:                 [8]byte{1, 2, 34, 31, 184, 122, 222, 111},
			ServerCookie:                 [32]byte{111, 34, 222, 194, 1, 22, 4, 11, 84, 34, 99, 99, 77, 23, 12},
			ServerCookieAdditionalLength: 16,
		})
	})
	expectPanic("optsb.ExtendedDNSError()", func() {
		optsb.ExtendedDNSError(EDNS0ExtendedDNSError{
			InfoCode:  1,
			ExtraText: []byte("error text"),
		})
	})
	optb2.End()
	if len(b.Bytes()) != 12 || b.Length() != 12 || b.Header() != *new(Header) {
		t.Fatalf("changes caused by EDNS0OptionBuilder visible before End()")
	}
	expectPanic("b.ResourceA()", func() {
		b.ResourceA(ResourceHeader{
			Name: MustParseName("example.com"),
		}, ResourceA{A: [4]byte{192, 0, 2, 1}})
	})
	optsb.End()

	p, _, err := Parse(b.Bytes())
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if err = p.StartAnswers(); err != nil {
		t.Fatalf("p.StartAnswers() unexpected error: %v", err)
	}
	if err = p.StartAuthorities(); err != nil {
		t.Fatalf("p.StartAuthorities() unexpected error: %v", err)
	}
	if err = p.StartAdditionals(); err != nil {
		t.Fatalf("p.StartAdditionals() unexpected error: %v", err)
	}

	hdr, err := p.ResourceHeader()
	if err != nil {
		t.Fatalf("p.ResourceHeader() unexpected error: %v", err)
	}
	if _, err = hdr.AsEDNS0Header(); err != nil {
		t.Fatalf("p.ResourceHeader().AsEDNS0Header() unexpected error: %v", err)
	}

	p2 := p
	resOPT, err := p2.ResourceOPT()
	if err != nil {
		t.Fatalf("p2.ResourceOPT() unexpected error: %v", err)
	}
	expectOPT := ResourceOPT{
		Options: []EDNS0Option{
			&EDNS0ClientSubnet{
				Family:             AddressFamilyIPv4,
				SourcePrefixLength: 8,
				ScopePrefixLength:  7,
				Address:            []byte{192, 0, 2, 1},
			},
			&EDNS0Cookie{
				ClientCookie:                 [8]byte{1, 2, 34, 31, 184, 122, 222, 111},
				ServerCookie:                 [32]byte{111, 34, 222, 194, 1, 22, 4, 11, 84, 34, 99, 99, 77, 23, 12},
				ServerCookieAdditionalLength: 16,
			},
			&EDNS0ExtendedDNSError{
				InfoCode:  1,
				ExtraText: []byte("error text"),
			}},
	}
	if len(resOPT.Options) != len(expectOPT.Options) {
		t.Fatalf("p2.ResourceOPT() = %#v, want: %#v", resOPT, expectOPT)
	}
	for i := 0; i < len(resOPT.Options); i++ {
		equalRData(t, fmt.Sprintf("p2.ResourceOPT().Options[%v]", i), expectOPT.Options[i], resOPT.Options[i])
	}

	optsp, err := p.ResourceOPTParser()
	if err != nil {
		t.Fatalf("p.ResourceOPTParser() unexpected error: %v", err)
	}

	code, err := optsp.Code()
	if err != nil {
		t.Fatalf("optsp.Code() unexpected error: %v", err)
	}
	if code != EDNS0OptionCodeClientSubnet {
		t.Fatalf("optsp.Code() = %v, want: %v", code, EDNS0OptionCodeClientSubnet)
	}

	clientSubnet, err := optsp.ClientSubnet()
	if err != nil {
		t.Fatalf("optsp.ClientSubnet() unexpected error: %v", err)
	}
	equalRData(t, "optsp.ClientSubnet()", clientSubnet, EDNS0ClientSubnet{
		Family:             AddressFamilyIPv4,
		SourcePrefixLength: 8,
		ScopePrefixLength:  7,
		Address:            []byte{192, 0, 2, 1},
	})

	code, err = optsp.Code()
	if err != nil {
		t.Fatalf("optsp.Code() unexpected error: %v", err)
	}
	if code != EDNS0OptionCodeCookie {
		t.Fatalf("optsp.Code() = %v, want: %v", code, EDNS0OptionCodeCookie)
	}

	cookie, err := optsp.Cookie()
	if err != nil {
		t.Fatalf("optsp.Cookie() unexpected error: %v", err)
	}
	equalRData(t, "optp.Cookie()", cookie, EDNS0Cookie{
		ClientCookie:                 [8]byte{1, 2, 34, 31, 184, 122, 222, 111},
		ServerCookie:                 [32]byte{111, 34, 222, 194, 1, 22, 4, 11, 84, 34, 99, 99, 77, 23, 12},
		ServerCookieAdditionalLength: 16,
	})

	code, err = optsp.Code()
	if err != nil {
		t.Fatalf("optsp.Code() unexpected error: %v", err)
	}
	if code != EDNS0OptionCodeExtendedDNSError {
		t.Fatalf("optsp.Code() = %v, want: %v", code, EDNS0OptionCodeExtendedDNSError)
	}

	extDNSError, err := optsp.ExtendedDNSError()
	if err != nil {
		t.Fatalf("optsp.ExtendedDNSError() unexpected error: %v", err)
	}
	equalRData(t, "optsp.ExtendedDNSError()", extDNSError, EDNS0ExtendedDNSError{
		InfoCode:  1,
		ExtraText: []byte("error text"),
	})

	code, err = optsp.Code()
	if err != nil {
		t.Fatalf("optsp.Code() unexpected error: %v", err)
	}
	if code != 55001 {
		t.Fatalf("optsp.Code() = %v, want: %v", code, EDNS0OptionCode(55001))
	}

	optp, err := optsp.OptionParser()
	if err != nil {
		t.Fatalf("optsp.OptionParser() unexpected error: %v", err)
	}

	n1, err := optp.Name()
	if err != nil {
		t.Fatalf("optp.Name() unexpected error: %v", err)
	}
	expectParserName(t, "n1 optp.Name()", n1, "example.com", false)

	n2, err := optp.Name()
	if err != nil {
		t.Fatalf("optp.Name() unexpected error: %v", err)
	}
	expectParserName(t, "n2 optp.Name()", n2, "example.com", true)

	n3, err := optp.Name()
	if err != nil {
		t.Fatalf("optp.Name() unexpected error: %v", err)
	}
	expectParserName(t, "n3 optp.Name()", n3, "www.example.com", true)

	n4, err := optp.Name()
	if err != nil {
		t.Fatalf("optp.Name() unexpected error: %v", err)
	}
	expectParserName(t, "n4 optp.Name()", n4, "www.example.com", false)

	if l := optp.Length(); l != 21 {
		t.Fatalf("optp.Length() = %v, want: 21", l)
	}

	u8, err := optp.Uint8()
	if err != nil {
		t.Fatalf("optp.Uint8() unexpected error: %v", err)
	}
	if u8 != 11 {
		t.Fatalf("optp.Uint8() = %v, want: 11", u8)
	}

	u16, err := optp.Uint16()
	if err != nil {
		t.Fatalf("optp.Uint16() unexpected error: %v", err)
	}
	if u16 != 22111 {
		t.Fatalf("optp.Uint8() = %v, want: 22111", u16)
	}

	u32, err := optp.Uint32()
	if err != nil {
		t.Fatalf("optp.Uint32() unexpected error: %v", err)
	}
	if u32 != 2283478384 {
		t.Fatalf("optp.Uint8() = %v, want: 2283478384", u32)
	}

	u64, err := optp.Uint64()
	if err != nil {
		t.Fatalf("optp.Uint64() unexpected error: %v", err)
	}
	if u64 != 9993422834783842 {
		t.Fatalf("optp.Uint8() = %v, want: 9993422834783842", u64)
	}

	if l := optp.Length(); l != 6 {
		t.Fatalf("optp.Length() = %v, want: 6", l)
	}

	b2, err := optp.Bytes(2)
	if err != nil {
		t.Fatalf("optp.Bytes(2) unexpected error: %v", err)
	}
	if !bytes.Equal([]byte{1, 2}, b2) {
		t.Fatalf("optp.Bytes(2) = %v, want: %v", b2, []byte{1, 2})
	}

	ab := optp.AllBytes()
	if !bytes.Equal([]byte{3, 4, 5, 6}, ab) {
		t.Fatalf("optp.Bytes(2) = %v, want: %v", ab, []byte{3, 4, 5, 6})
	}

	if l := optp.Length(); l != 0 {
		t.Fatalf("optp.Length() = %v, want: 0", l)
	}

	if err = optp.End(); err != nil {
		t.Fatalf("optp.End() unexpected error: %v", err)
	}
}

func expectParserName(t *testing.T, prefix string, name Name, expectNameAsStr string, comressed bool) {
	if !bytes.Equal(nameAsSlice(expectNameAsStr), name.asSlice()) {
		t.Fatalf("%v = %v, want: %v", prefix, name.String(), expectNameAsStr)
	}
	c := name.Compression == CompressionCompressed
	if c != comressed {
		t.Fatalf("%v.Compressed = %v, want: %v", prefix, c, comressed)
	}
}

func TestResourceOPTEncodingLength(t *testing.T) {
	const msgLimit = 1024

	EDNS0Hdr := EDNS0Header{
		Payload:              1111,
		PartialExtendedRCode: 0,
		Version:              0,
		ExtendedFlags:        0,
	}
	resOPT := ResourceOPT{
		Options: []EDNS0Option{
			&EDNS0ClientSubnet{
				Family:             AddressFamilyIPv4,
				SourcePrefixLength: 8,
				ScopePrefixLength:  7,
				Address:            []byte{192, 0, 2, 1},
			},
			&EDNS0Cookie{
				ClientCookie:                 [8]byte{1, 2, 34, 31, 184, 122, 222, 111},
				ServerCookie:                 [32]byte{111, 34, 222, 194, 1, 22, 4, 11, 84, 34, 99, 99, 77, 23, 12},
				ServerCookieAdditionalLength: 16,
			},
			&EDNS0ExtendedDNSError{
				InfoCode:  1,
				ExtraText: []byte("error text"),
			}},
	}

	b := StartBuilder(make([]byte, 0, msgLimit), 0, 0)
	b.LimitMessageSize(msgLimit - (EDNS0HeaderEncodingLength + resOPT.EncodingLength()))
	b.StartAnswers()

	for {
		err := b.ResourceA(ResourceHeader{
			Name: MustParseName("example.com"),
		}, ResourceA{A: [4]byte{192, 0, 2, 1}})
		if err != nil {
			if err == ErrTruncated {
				break
			}
			t.Fatalf("b.ResourceA() unexpected error: %v", err)
		}
	}

	b.LimitMessageSize(msgLimit)
	b.StartAuthorities()
	b.StartAdditionals()

	if err := b.ResourceOPT(EDNS0Hdr.AsResourceHeader(), resOPT); err != nil {
		t.Fatalf("b.ResourceOPT() unexpected error: %v", err)
	}

	err := b.ResourceA(ResourceHeader{
		Name: MustParseName("example.com"),
	}, ResourceA{A: [4]byte{192, 0, 2, 1}})
	if err != ErrTruncated {
		t.Fatalf("b.ResourceA() unexpected error: %v, want: %v", err, ErrTruncated)
	}

	if b.Length() > msgLimit {
		t.Fatalf("b.Length() = %v, want <= %v", b.Length(), msgLimit)
	}

	p, _, err := Parse(b.Bytes())
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if err = p.StartAnswers(); err != nil {
		t.Fatalf("p.StartAnswers() unexpected error: %v", err)
	}
	for {
		if _, err = p.ResourceHeader(); err != nil {
			if err == ErrSectionDone {
				break
			}
			t.Fatalf("p.ResourceHeader() unexpected error: %v", err)
		}
		if _, err = p.ResourceA(); err != nil {
			t.Fatalf("p.ResourceA() unexpected error: %v", err)
		}
	}

	if err = p.StartAuthorities(); err != nil {
		t.Fatalf("p.StartAuthorities() unexpected error: %v", err)
	}
	if err = p.StartAdditionals(); err != nil {
		t.Fatalf("p.StartAdditionals() unexpected error: %v", err)
	}

	rhdr, err := p.ResourceHeader()
	if err != nil {
		t.Fatalf("p.ResourceHeader() unexpected error: %v", err)
	}

	if _, err = rhdr.AsEDNS0Header(); err != nil {
		t.Fatalf("p.ResourceHeader().AsEDNS0Header() unexpected error: %v", err)
	}

	opt, err := p.ResourceOPT()
	if err != nil {
		t.Fatalf("p.ResourceOPT() unexpected error: %v", err)
	}

	if len(resOPT.Options) != len(opt.Options) {
		t.Fatalf("p2.ResourceOPT() = %#v, want: %#v", opt, resOPT)
	}
	for i := 0; i < len(resOPT.Options); i++ {
		equalRData(t, fmt.Sprintf("p2.ResourceOPT().Options[%v]", i), opt.Options[i], resOPT.Options[i])
	}
}
