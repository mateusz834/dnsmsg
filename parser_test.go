package dnsmsg

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestParse(t *testing.T) {
	expect := Header{
		ID:      43127,
		Flags:   Flags(12930),
		QDCount: 49840,
		ANCount: 55119,
		NSCount: 33990,
		ARCount: 62101,
	}

	raw := binary.BigEndian.AppendUint16(make([]byte, 0, 12), expect.ID)
	raw = binary.BigEndian.AppendUint16(raw, uint16(expect.Flags))
	raw = binary.BigEndian.AppendUint16(raw, expect.QDCount)
	raw = binary.BigEndian.AppendUint16(raw, expect.ANCount)
	raw = binary.BigEndian.AppendUint16(raw, expect.NSCount)
	raw = binary.BigEndian.AppendUint16(raw, expect.ARCount)

	p, hdr, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}

	if hdr != expect {
		t.Fatalf("Parse() unexpected header: %#v, want: %#v", hdr, expect)
	}

	_, err = p.Question()
	if err != errInvalidDNSName {
		t.Fatalf("p.Question() unexpected error: %v, want: %v", err, errInvalidDNSName)
	}

	_, _, err = Parse(raw[:11])
	if err == nil {
		t.Fatal("Parse(raw[:11]): unexpected success while parsing too short dns message")
	}
}

func TestParseQuestion(t *testing.T) {
	raw := binary.BigEndian.AppendUint16(make([]byte, 0, 12), 0)
	raw = binary.BigEndian.AppendUint16(raw, 0)
	raw = binary.BigEndian.AppendUint16(raw, 2)
	raw = binary.BigEndian.AppendUint16(raw, 0)
	raw = binary.BigEndian.AppendUint16(raw, 0)
	raw = binary.BigEndian.AppendUint16(raw, 0)

	raw = append(raw, []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}...)
	raw = binary.BigEndian.AppendUint16(raw, 1)
	raw = binary.BigEndian.AppendUint16(raw, 1)

	raw = append(raw, []byte{3, 'w', 'w', 'w', 0xC0, 12}...)
	raw = binary.BigEndian.AppendUint16(raw, 45938)
	raw = binary.BigEndian.AppendUint16(raw, 23819)

	p, hdr, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}

	expect := Header{QDCount: 2}
	if hdr != expect {
		t.Errorf("Parse() unexpected header: %#v, want: %#v", hdr, expect)
	}

	q1, err := p.Question()
	if err != nil {
		t.Fatalf("p.Question() unexpected error: %v", err)
	}

	n := MustParseName("example.com")
	if !q1.Name.Equal(&n) {
		t.Errorf(`q1.Name = %v, q1.Name.EqualName(MustNewName("example.com")) = false, want: true`, q1.Name.String())
	}

	if q1.Type != TypeA {
		t.Errorf(`q1.Type = %v, want: %v`, q1.Type, TypeA)
	}

	if q1.Class != ClassIN {
		t.Errorf(`q1.Class = %v, want: %v`, q1.Class, ClassIN)
	}

	q2, err := p.Question()
	if err != nil {
		t.Fatalf("p.Question() unexpected error: %v", err)
	}

	n = MustParseName("www.example.com")
	if !q2.Name.Equal(&n) {
		t.Errorf(`q2.Name = %v, q2.Name.EqualName(MustNewName("www.example.com")) = false, want: true`, q2.Name.String())
	}

	if q2.Type != 45938 {
		t.Errorf(`q2.Type = %v, want: %v`, q2.Type, Type(45938))
	}

	if q2.Class != 23819 {
		t.Errorf(`q2.Class = %v, want: %v`, q2.Class, Class(23819))
	}

	if _, err := p.Question(); err != ErrSectionDone {
		t.Fatalf("p.Question() unexpected error after parsing all questions: %v, want: %v", err, ErrSectionDone)
	}

	if err := p.End(); err != nil {
		t.Fatalf("p.End() unexpected error: %v", err)
	}

	err = p.SkipQuestions()
	if err != nil {
		t.Fatalf("p.SkipQuestions() unexpected error: %v", err)
	}
}

func TestParseResourceHeader(t *testing.T) {
	raw := binary.BigEndian.AppendUint16(make([]byte, 0, 12), 0)
	raw = binary.BigEndian.AppendUint16(raw, 0)
	raw = binary.BigEndian.AppendUint16(raw, 0)
	raw = binary.BigEndian.AppendUint16(raw, 1)
	raw = binary.BigEndian.AppendUint16(raw, 1)
	raw = binary.BigEndian.AppendUint16(raw, 3)

	raw = append(raw, []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}...)
	raw = binary.BigEndian.AppendUint16(raw, 1)
	raw = binary.BigEndian.AppendUint16(raw, 1)
	raw = binary.BigEndian.AppendUint32(raw, 3600)
	raw = binary.BigEndian.AppendUint16(raw, 4)
	raw = append(raw, 192, 0, 2, 1)

	raw = append(raw, []byte{3, 'w', 'w', 'w', 0xC0, 12}...)
	raw = binary.BigEndian.AppendUint16(raw, 1)
	raw = binary.BigEndian.AppendUint16(raw, 1)
	raw = binary.BigEndian.AppendUint32(raw, 3600)
	raw = binary.BigEndian.AppendUint16(raw, 4)
	raw = append(raw, 192, 0, 2, 1)

	raw = append(raw, []byte{4, 's', 'm', 't', 'p', 0xC0, 12}...)
	raw = binary.BigEndian.AppendUint16(raw, 1)
	raw = binary.BigEndian.AppendUint16(raw, 1)
	raw = binary.BigEndian.AppendUint32(raw, 3600)
	raw = binary.BigEndian.AppendUint16(raw, 4)
	raw = append(raw, 192, 0, 2, 1)

	raw = append(raw, []byte{4, 's', 'm', 't', 'p', 0xC0, 12}...)
	raw = binary.BigEndian.AppendUint16(raw, 45182)
	raw = binary.BigEndian.AppendUint16(raw, 52833)
	raw = binary.BigEndian.AppendUint32(raw, 39483)
	raw = binary.BigEndian.AppendUint16(raw, 1223)
	raw = append(raw, make([]byte, 1223)...)

	raw = append(raw, []byte{4, 's', 'm', 't', 'p', 0xC0, 12}...)
	raw = binary.BigEndian.AppendUint16(raw, 45182)
	raw = binary.BigEndian.AppendUint16(raw, 52833)
	raw = binary.BigEndian.AppendUint32(raw, 39483)
	raw = binary.BigEndian.AppendUint16(raw, 0)

	p, hdr, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}

	expect := Header{ANCount: 1, NSCount: 1, ARCount: 3}
	if hdr != expect {
		t.Fatalf("Parse() unexpected header: %#v, want: %#v", hdr, expect)
	}

	if _, err := p.Question(); err != ErrSectionDone {
		t.Fatalf("p.Question() unexpected error while parsing zero-count questions section: %v, want: %v", err, ErrSectionDone)
	}

	expectNames := []string{"example.com", "www.example.com", "smtp.example.com"}
	sectionNames := []string{"Questions", "Answers", "Authorities", "Additionals"}
	for i, nextSection := range []func() error{p.StartAnswers, p.StartAuthorities, p.StartAdditionals} {
		curSectionName := sectionNames[i+1]
		if err := nextSection(); err != nil {
			t.Fatalf("%v section, p.Start%v(): unexpected error: %v", sectionNames[i], curSectionName, err)
		}

		rhdr, err := p.ResourceHeader()
		if err != nil {
			t.Fatalf("%v section, p.ResourceHeader(): unexpected error: %v", curSectionName, err)
		}

		n := MustParseName(expectNames[i])
		if !rhdr.Name.Equal(&n) {
			t.Errorf(`%v section, rhdr.Name = %v, rhdr.Name.EqualName(MustNewName("%v")) = false, want: true`, curSectionName, rhdr.Name.String(), expectNames[i])
		}

		if rhdr.Type != TypeA {
			t.Errorf("%v section, rdhr.Type = %v, want: %v", curSectionName, rhdr.Type, TypeA)
		}

		if rhdr.Class != ClassIN {
			t.Errorf("%v section, rdhr.Class = %v, want: %v", curSectionName, rhdr.Class, ClassIN)
		}

		if rhdr.TTL != 3600 {
			t.Errorf("%v section, rdhr.TTL = %v, want: 3600", curSectionName, rhdr.TTL)
		}

		if rhdr.Length != 4 {
			t.Errorf("%v section, rdhr.Length = %v, want: 4", curSectionName, rhdr.Length)
		}

		resourceA, err := p.ResourceA()
		if err != nil {
			t.Fatalf("%v section, p.ResourceA() unexpected error: %v", curSectionName, err)
		}

		expect := ResourceA{[4]byte{192, 0, 2, 1}}
		if resourceA != expect {
			t.Errorf("%v section, p.ResourceA() = %v, want: %v", curSectionName, resourceA, expect)
		}

		if i != 2 {
			_, err = p.ResourceHeader()
			if err != ErrSectionDone {
				t.Fatalf("%v section, p.ResourceHeader() unexpected error: %v, want: %v", curSectionName, err, ErrSectionDone)
			}
		}
	}

	rhdr2, err := p.ResourceHeader()
	if err != nil {
		t.Fatalf("p.ResourceHeader(): unexpected error: %v", err)
	}

	n := MustParseName("smtp.example.com")
	if !rhdr2.Name.Equal(&n) {
		t.Errorf(`rhdr2.Name = %v, rhdr2.Name.EqualName(MustNewName("smtp.example.com.")) = false, want: true`, rhdr2.Name.String())
	}

	if rhdr2.Type != 45182 {
		t.Errorf("rhdr2.Type = %v, want: %v", rhdr2.Type, Type(45182))
	}

	if rhdr2.Class != 52833 {
		t.Errorf("rhdr2.Class = %v, want: %v", rhdr2.Class, Class(52833))
	}

	if rhdr2.TTL != 39483 {
		t.Errorf("rhdr2.TTL = %v, want: 39483", rhdr2.TTL)
	}

	if rhdr2.Length != 1223 {
		t.Errorf("rhdr2.Length = %v, want: 1223", rhdr2.Length)
	}

	if err := p.SkipResourceData(); err != nil {
		t.Fatalf("p.SkipResourceData() unexpected error: %v", err)
	}

	rhdr3, err := p.ResourceHeader()
	if err != nil {
		t.Fatalf("p.ResourceHeader() unexpected error: %v", err)
	}

	n = MustParseName("smtp.example.com.")
	if !rhdr3.Name.Equal(&n) {
		t.Errorf(`rhdr3.Name = %v, rhdr3.Name.EqualName(MustNewName("smtp.example.com.")) = false, want: true`, rhdr3.Name.String())
	}

	if rhdr3.Type != 45182 {
		t.Errorf("rhdr3.Type = %v, want: %v", rhdr3.Type, Type(45182))
	}

	if rhdr3.Class != 52833 {
		t.Errorf("rhdr3.Class = %v, want: %v", rhdr3.Class, Class(52833))
	}

	if rhdr3.TTL != 39483 {
		t.Errorf("rhdr3.TTL = %v, want: 39483", rhdr3.TTL)
	}

	if rhdr3.Length != 0 {
		t.Errorf("rhdr3.Length = %v, want: 0", rhdr3.Length)
	}

	if err := p.SkipResourceData(); err != nil {
		t.Fatalf("p.SkipResourceData() unexpected error: %v", err)
	}

	_, err = p.ResourceHeader()
	if err != ErrSectionDone {
		t.Fatalf("p.ResourceHeader() unexpected error: %v, want: %v", err, ErrSectionDone)
	}

	if err := p.End(); err != nil {
		t.Fatalf("p.End() unexpected error: %v", err)
	}
}

func TestZeroLengthRData(t *testing.T) {
	raw := binary.BigEndian.AppendUint16(make([]byte, 0, 12), 0)
	raw = binary.BigEndian.AppendUint16(raw, 0)
	raw = binary.BigEndian.AppendUint16(raw, 0)
	raw = binary.BigEndian.AppendUint16(raw, 1)
	raw = binary.BigEndian.AppendUint16(raw, 0)
	raw = binary.BigEndian.AppendUint16(raw, 0)

	raw = append(raw, []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}...)
	raw = binary.BigEndian.AppendUint16(raw, 1)
	raw = binary.BigEndian.AppendUint16(raw, 1)
	raw = binary.BigEndian.AppendUint32(raw, 3600)
	raw = binary.BigEndian.AppendUint16(raw, 0)

	p, _, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}

	if err := p.StartAnswers(); err != nil {
		t.Fatalf("p.StartAnswers() unexpected error: %v", err)
	}

	if _, err := p.ResourceHeader(); err != nil {
		t.Fatalf("p.ResourceHeader(): unexpected error: %v", err)
	}

	if _, err := p.ResourceHeader(); err != errInvalidOperation {
		t.Fatalf("p.ResourceHeader() unexpected error: %v, want %v", err, errInvalidOperation)
	}

	if err := p.SkipResourceData(); err != nil {
		t.Fatalf("p.SkipResourceData() unexpected error: %v", err)
	}

	if _, err := p.ResourceHeader(); err != ErrSectionDone {
		t.Fatalf("p.ResourceHeader() unexpected error: %v, want %v", err, ErrSectionDone)
	}
}

func TestParserRDParser(t *testing.T) {
	raw := binary.BigEndian.AppendUint16(make([]byte, 0, 12), 0)
	raw = binary.BigEndian.AppendUint16(raw, 0)
	raw = binary.BigEndian.AppendUint16(raw, 0)
	raw = binary.BigEndian.AppendUint16(raw, 3)
	raw = binary.BigEndian.AppendUint16(raw, 0)
	raw = binary.BigEndian.AppendUint16(raw, 0)

	raw = append(raw, []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}...)
	raw = binary.BigEndian.AppendUint16(raw, 0)
	raw = binary.BigEndian.AppendUint16(raw, 0)
	raw = binary.BigEndian.AppendUint32(raw, 0)
	raw = binary.BigEndian.AppendUint16(raw, 26)

	raw = append(raw, 0xC0, 12)
	raw = append(raw, 221, 201, 32, 87)
	raw = append(raw, 3, 'w', 'w', 'w', 0xC0, 12)
	raw = binary.BigEndian.AppendUint16(raw, 45738)
	raw = binary.BigEndian.AppendUint32(raw, 3384745738)
	raw = binary.BigEndian.AppendUint64(raw, 9837483247384745738)

	raw = append(raw, []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}...)
	raw = binary.BigEndian.AppendUint16(raw, 1)
	raw = binary.BigEndian.AppendUint16(raw, 1)
	raw = binary.BigEndian.AppendUint32(raw, 3600)
	raw = binary.BigEndian.AppendUint16(raw, 0)

	raw = append(raw, []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}...)
	raw = binary.BigEndian.AppendUint16(raw, 1)
	raw = binary.BigEndian.AppendUint16(raw, 1)
	raw = binary.BigEndian.AppendUint32(raw, 3600)
	raw = binary.BigEndian.AppendUint16(raw, 4)
	raw = append(raw, 192, 0, 2, 1)

	p, _, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}

	if err := p.StartAnswers(); err != nil {
		t.Fatalf("p.StartAnswers() unexpected error: %v", err)
	}

	if _, err := p.ResourceHeader(); err != nil {
		t.Fatalf("p.ResourceHeader(): unexpected error: %v", err)
	}

	rdp, err := p.RDParser()
	if err != nil {
		t.Fatalf("p.RDParser(): unexpected error: %v", err)
	}

	if _, err := p.ResourceHeader(); err != nil {
		t.Fatalf("p.ResourceHeader(): unexpected error: %v", err)
	}

	if err := p.SkipResourceData(); err != nil {
		t.Fatalf("p.SkipResourceData() unexpected error: %v", err)
	}

	if l := rdp.Length(); l != 26 {
		t.Errorf("rdp.Length() = %v, want: 26", l)
	}

	name, err := rdp.Name()
	if err != nil {
		t.Fatalf("rdp.Name() unexpected error: %v", err)
	}

	n := MustParseName("example.com")
	if !name.Equal(&n) {
		t.Errorf(`rdp.Name() = %v, rdp.Name().EqualName(MustNewName("example.com")) = false, want: true`, name.String())
	}

	u8, err := rdp.Uint8()
	if err != nil {
		t.Fatalf("rdp.Uint8() unexpected error: %v", err)
	}
	if u8 != 221 {
		t.Errorf("rdp.Uint8() = %v, want: 221", u8)
	}

	if l := rdp.Length(); l != 23 {
		t.Errorf("rdp.Length() = %v, want: 23", l)
	}

	rawBytes, err := rdp.Bytes(3)
	if err != nil {
		t.Fatalf("rdp.Bytes() unexpected error: %v", err)
	}
	expect := []byte{201, 32, 87}
	if !bytes.Equal(rawBytes, expect) {
		t.Errorf("rdp.Bytes() = %v, want %v", rawBytes, expect)
	}

	name, err = rdp.Name()
	if err != nil {
		t.Fatalf("rdp.Name() unexpected error: %v", err)
	}

	n = MustParseName("www.example.com")
	if !name.Equal(&n) {
		t.Errorf(`rdp.Name() = %v, rdp.Name().EqualName(MustNewName("www.example.com")) = false, want: true`, name.String())
	}

	u16, err := rdp.Uint16()
	if err != nil {
		t.Fatalf("rdp.Uint16() unexpected error: %v", err)
	}
	if u16 != 45738 {
		t.Errorf("rdp.Uint16() = %v, want: 45738", u16)
	}

	u32, err := rdp.Uint32()
	if err != nil {
		t.Fatalf("rdp.Uint32() unexpected error: %v", err)
	}
	if u32 != 3384745738 {
		t.Errorf("rdp.Uint32() = %v, want: 3384745738", u32)
	}

	u64, err := rdp.Uint64()
	if err != nil {
		t.Fatalf("rdp.Uint64() unexpected error: %v", err)
	}
	if u64 != 9837483247384745738 {
		t.Errorf("rdp.Uint64() = %v, want: 9837483247384745738", u64)
	}

	if l := rdp.Length(); l != 0 {
		t.Errorf("rdp.Length() = %v, want: 0", l)
	}

	if err := rdp.End(); err != nil {
		t.Fatalf("p.End(): unexpected error: %v", err)
	}

	if _, err := p.ResourceHeader(); err != nil {
		t.Fatalf("p.ResourceHeader(): unexpected error: %v", err)
	}

	rdp2, err := p.RDParser()
	if err != nil {
		t.Fatalf("p.RDParser(): unexpected error: %v", err)
	}

	if _, err := rdp2.Uint8(); err != nil {
		t.Fatalf("rdp2.Uint8() unexpected error: %v", err)
	}

	rawBytes = rdp2.AllBytes()
	expect = []byte{0, 2, 1}
	if !bytes.Equal(rawBytes, expect) {
		t.Errorf("rdp2.AllBytes() = %v, want: %v", rawBytes, expect)
	}

	if err := rdp2.End(); err != nil {
		t.Fatalf("rdp2.End(): unexpected error: %v", err)
	}
}

func TestParserInvalidOperation(t *testing.T) {
	b := StartBuilder(make([]byte, 0, 512), 0, 0)

	b.Question(Question{
		Name:  MustParseName("example.com"),
		Type:  TypeA,
		Class: ClassIN,
	})

	for _, nextSection := range []func(){b.StartAnswers, b.StartAuthorities, b.StartAdditionals} {
		nextSection()
		hdr := ResourceHeader{
			Name:  MustParseName("example.com"),
			Class: ClassIN,
			TTL:   60,
		}
		b.ResourceA(hdr, ResourceA{A: [4]byte{192, 0, 2, 1}})
		b.ResourceAAAA(hdr, ResourceAAAA{AAAA: netip.MustParseAddr("2001:db8::1").As16()})
		b.ResourceNS(hdr, ResourceNS{NS: MustParseName("ns1.example.com")})
		b.ResourceSOA(hdr, ResourceSOA{
			NS:      MustParseName("ns1.example.com"),
			Mbox:    MustParseName("admin.example.com"),
			Serial:  2022010199,
			Refresh: 3948793,
			Retry:   34383744,
			Expire:  1223999999,
			Minimum: 123456789,
		})
		b.ResourcePTR(hdr, ResourcePTR{PTR: MustParseName("ns1.example.com")})
		b.ResourceTXT(hdr, ResourceTXT{TXT: [][]byte{[]byte("test"), []byte("test2")}})
		b.RawResourceTXT(hdr, RawResourceTXT{[]byte{1, 'a', 2, 'b', 'a'}})
		b.ResourceCNAME(hdr, ResourceCNAME{CNAME: MustParseName("www.example.com")})
		b.ResourceMX(hdr, ResourceMX{Pref: 100, MX: MustParseName("smtp.example.com")})
		b.ResourceOPT(hdr, ResourceOPT{Options: []EDNS0Option{
			&EDNS0ClientSubnet{Family: AddressFamilyIPv4, SourcePrefixLength: 2, ScopePrefixLength: 3, Address: []byte{192, 0, 2, 1}},
			&EDNS0Cookie{
				ClientCookie:                 [8]byte{21, 200, 93, 34, 5, 219, 17, 28},
				ServerCookie:                 [32]byte{1, 2, 3, 4, 5, 6, 7, 99, 234, 139, 99, 119},
				ServerCookieAdditionalLength: 12,
			},
			&EDNS0ExtendedDNSError{InfoCode: 1, ExtraText: []byte("some error Text")},
		}})
	}

	p, hdr, err := Parse(b.Bytes())
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}

	knownResourceTypes := []Type{TypeA, TypeAAAA, TypeNS, TypeSOA, TypePTR, TypeTXT, TypeCNAME, TypeMX, TypeOPT}
	parseResource := func(p *Parser, resType Type) error {
		switch resType {
		case TypeA:
			_, err = p.ResourceA()
		case TypeAAAA:
			_, err = p.ResourceAAAA()
		case TypeNS:
			_, err = p.ResourceNS()
		case TypeSOA:
			_, err = p.ResourceSOA()
		case TypePTR:
			_, err = p.ResourcePTR()
		case TypeTXT:
			_, err = p.RawResourceTXT()
		case TypeCNAME:
			_, err = p.ResourceCNAME()
		case TypeMX:
			_, err = p.ResourceMX()
		case TypeOPT:
			_, err = p.ResourceOPT()
		default:
			panic("unknown resource")
		}
		return err
	}

	if err := p.SkipResources(); err != errInvalidOperation {
		t.Fatalf("p.SkipResources() unexpected error: %v, want: %v", err, errInvalidOperation)
	}

	if err := p.SkipResourceData(); err != errInvalidOperation {
		t.Fatalf("p.SkipResourceData() unexpected error: %v, want: %v", err, errInvalidOperation)
	}

	if _, err := p.RDParser(); err != errInvalidOperation {
		t.Fatalf("p.RDParser() unexpected error: %v, want: %v", err, errInvalidOperation)
	}

	for _, tt := range knownResourceTypes {
		if err := parseResource(&p, tt); err != errInvalidOperation {
			t.Fatalf("parseResource unexpected error while parsing %v resource: %v, want: %v", tt, err, errInvalidOperation)
		}
	}

	sectionNames := []string{"Questions", "Answers", "Authorities", "Additionals"}
	for i, next := range []func() error{p.StartAnswers, p.StartAuthorities, p.StartAdditionals} {
		if err := next(); err != errInvalidOperation {
			t.Fatalf("p.Start%v(): %v, want: %v", sectionNames[i+1], err, errInvalidOperation)
		}
	}

	_, err = p.Question()
	if err != nil {
		t.Fatal(err)
	}

	if err := p.SkipResources(); err != errInvalidOperation {
		t.Fatalf("p.SkipResources() unexpected error: %v, want: %v", err, errInvalidOperation)
	}

	if err := p.SkipResourceData(); err != errInvalidOperation {
		t.Fatalf("p.SkipResourceData() unexpected error: %v, want: %v", err, errInvalidOperation)
	}

	if _, err := p.RDParser(); err != errInvalidOperation {
		t.Fatalf("p.RDParser(): unexpected error: %v, want: %v", err, errInvalidOperation)
	}

	for _, tt := range knownResourceTypes {
		if err := parseResource(&p, tt); err != errInvalidOperation {
			t.Fatalf("parseResource unexpected error while parsing %v resource: %v, want: %v", tt, err, errInvalidOperation)
		}
	}

	for i, next := range []func() error{p.StartAuthorities, p.StartAdditionals} {
		if err := next(); err != errInvalidOperation {
			t.Fatalf("p.Start%v(): %v, want: %v", sectionNames[i+2], err, errInvalidOperation)
		}
	}

	expectCounts := []uint16{hdr.ANCount, hdr.NSCount, hdr.ARCount}
	changeSections := []func() error{p.StartAnswers, p.StartAuthorities, p.StartAdditionals}
	for curSection, nextSection := range changeSections {
		sectionName := sectionNames[curSection+1]
		if err := nextSection(); err != nil {
			t.Fatalf("%v section, p.Start%v(): unexpected error: %v", sectionNames[curSection], sectionName, err)
		}

		for count := expectCounts[curSection]; ; count-- {
			if _, err := p.Question(); err != errInvalidOperation {
				t.Fatalf("%v section, p.Question(): unexpected error: %v", sectionName, err)
			}

			if err := p.SkipQuestions(); err != errInvalidOperation {
				t.Fatalf("%v section, p.SkipQuestions(): unexpected error: %v", sectionName, err)
			}

			invalidChangeSection := changeSections
			invalidSectionNames := sectionNames[1:]
			if count == 0 {
				switch curSection {
				case 0:
					invalidChangeSection = []func() error{p.StartAnswers, p.StartAdditionals}
					invalidSectionNames = []string{"Answers", "Additionals"}
				case 1:
					invalidChangeSection = []func() error{p.StartAnswers, p.StartAuthorities}
					invalidSectionNames = []string{"Answers", "Authorities"}
				}
			}

			for i, next := range invalidChangeSection {
				if err := next(); err != errInvalidOperation {
					t.Fatalf("%v section, p.Start%v(): %v, want: %v", sectionName, invalidSectionNames[i], err, errInvalidOperation)
				}
			}

			if err := p.SkipResourceData(); err != errInvalidOperation {
				t.Fatalf("%v section, p.SkipResourceData() unexpected error: %v, want: %v", sectionName, err, errInvalidOperation)
			}

			if _, err := p.RDParser(); err != errInvalidOperation {
				t.Fatalf("%v section, p.RDParser(): unexpected error: %v, want: %v", sectionName, err, errInvalidOperation)
			}

			for _, tt := range knownResourceTypes {
				if err := parseResource(&p, tt); err != errInvalidOperation {
					t.Fatalf("%v section, parseResource unexpected error while parsing %v resource: %v, want: %v", sectionName, tt, err, errInvalidOperation)
				}
			}

			rhdr, err := p.ResourceHeader()
			if err != nil {
				if err == ErrSectionDone {
					break
				}
				t.Fatalf("%v section, p.ResourceHeader() unexpected error: %v", sectionName, err)
			}

			_, err = p.ResourceHeader()
			if err != errInvalidOperation {
				t.Fatalf("%v section, p.ResourceHeader() unexpected error: %v, want: %v", sectionName, err, errInvalidOperation)
			}

			if _, err := p.Question(); err != errInvalidOperation {
				t.Fatalf("%v section, p.Question() unexpected error: %v, want %v", sectionName, err, errInvalidOperation)
			}

			if err := p.SkipQuestions(); err != errInvalidOperation {
				t.Fatalf("%v section, p.SkipQuestions() unexpected error: %v, want %v", sectionName, err, errInvalidOperation)
			}

			for i, next := range changeSections {
				if err := next(); err != errInvalidOperation {
					t.Fatalf("%v section, p.Start%v(): %v, want: %v", sectionName, sectionNames[i+1], err, errInvalidOperation)
				}
			}

			for _, tt := range knownResourceTypes {
				if rhdr.Type != tt {
					if err := parseResource(&p, tt); err != errInvalidOperation {
						t.Fatalf("%v section, parseResource unexpected error while parsing %v resource: %v, want: %v", sectionName, tt, err, errInvalidOperation)
					}
				}
			}

			if err := parseResource(&p, rhdr.Type); err != nil {
				t.Fatalf("%v section, parseResource unexpected error while parsing %v resource: %v", sectionName, rhdr.Type, err)
			}
		}
	}
}

func FuzzParser(f *testing.F) {
	b := StartBuilder(nil, 0, 0)
	b.Question(Question{
		Name:  MustParseName("example.com"),
		Type:  TypeA,
		Class: ClassIN,
	})
	b.StartAnswers()
	b.ResourceA(ResourceHeader{
		Name:  MustParseName("example.com"),
		Class: ClassIN,
		TTL:   60,
	}, ResourceA{A: [4]byte{192, 0, 2, 1}})
	f.Add(b.Bytes(), false, false, false, false, 100, false)

	// TODO: do something like
	// unpack -> pack -> unpack and assert that both unpack returned the same things.

	f.Fuzz(func(t *testing.T, msg []byte, skipQuestions, skipAnswers, skipAuthorities, skipAddtionals bool, skipRData int, useRDParser bool) {
		p, hdr, err := Parse(msg)
		if err != nil {
			return
		}

		if skipQuestions {
			err := p.SkipQuestions()
			if err != nil {
				if err == errInvalidOperation {
					t.Fatalf("p.SkipQuestions(): unexpected error: %v", err)
				}
				return
			}
			hdr.QDCount = 0
		}

		for count := 0; ; count++ {
			_, err := p.Question()
			if err != nil {
				if err == errInvalidOperation {
					t.Fatalf("p.Question(): unexpected error: %v", err)
				}
				if err == ErrSectionDone {
					if count != int(hdr.QDCount) {
						t.Errorf("unexpected amount of questions, got: %v, expected: %v", count, hdr.QDCount)
					}
					if _, err := p.Question(); err != ErrSectionDone {
						t.Fatalf("p.Question() unexpected error: %v, want: %v", err, ErrSectionDone)
					}
					break
				}
				return
			}
		}

		sectionNames := []string{"Questions", "Answers", "Authorities", "Additionals"}
		skipAll := []bool{skipAnswers, skipAuthorities, skipAddtionals}
		expectCounts := []uint16{hdr.ANCount, hdr.NSCount, hdr.ARCount}
		for i, nextSection := range []func() error{p.StartAnswers, p.StartAuthorities, p.StartAdditionals} {
			curSectionName := sectionNames[i+1]
			if err := nextSection(); err != nil {
				t.Fatalf("%v section, p.Start%v() unexpected error: %v", sectionNames[i], curSectionName, err)
			}

			if skipAll[i] {
				err := p.SkipResources()
				if err != nil {
					if err == errInvalidOperation {
						t.Fatalf("%v section, p.SkipResources(): unexpected error: %v", curSectionName, err)
					}
					return
				}
				expectCounts[i] = 0
			}

			for count := 0; ; count++ {
				hdr, err := p.ResourceHeader()
				if err != nil {
					if err == errInvalidOperation {
						t.Fatalf("%v section, p.ResourceHeader(): unexpected error: %v", curSectionName, err)
					}
					if err == ErrSectionDone {
						if count != int(expectCounts[i]) {
							t.Errorf("unexpected amount of resources, got: %v, expected: %v", count, expectCounts[i])
						}
						if _, err := p.ResourceHeader(); err != ErrSectionDone {
							t.Fatalf("%v section, p.ResourceHeader(): unexpected error: %v, want: %v", curSectionName, err, ErrSectionDone)
						}
						break
					}
					return
				}

				if count == skipRData {
					skipRData += skipRData / 2
					err := p.SkipResourceData()
					if err != nil {
						if err == errInvalidOperation {
							t.Fatalf("%v section, p.SkipResourceData(): unexpected error: %v", curSectionName, err)
						}
						return
					}
				} else if useRDParser {
					rdp, err := p.RDParser()
					if err != nil {
						if err == errInvalidOperation {
							t.Fatalf("%v section, p.RDParser(): unexpected error: %v", curSectionName, err)
						}
						return
					}
					rdp.Length()
					rdp.Name()
					rdp.Bytes(3)
					rdp.Uint8()
					rdp.Uint16()
					rdp.Uint32()
					rdp.Length()
					rdp.Uint64()
					rdp.Bytes(128)
					rdp.Length()
					rdp.AllBytes()
				} else {
					var err error
					switch hdr.Type {
					case TypeA:
						_, err = p.ResourceA()
					case TypeAAAA:
						_, err = p.ResourceAAAA()
					case TypeNS:
						_, err = p.ResourceNS()
					case TypeCNAME:
						_, err = p.ResourceCNAME()
					case TypeSOA:
						_, err = p.ResourceSOA()
					case TypePTR:
						_, err = p.ResourcePTR()
					case TypeMX:
						_, err = p.ResourceMX()
					case TypeTXT:
						var txt RawResourceTXT
						txt, err = p.RawResourceTXT()
						txt.ToResourceTXT()
					case TypeOPT:
						_, err = p.ResourceOPT()
					default:
						err = p.SkipResourceData()
					}
					if err != nil {
						if err == errInvalidOperation {
							t.Fatalf("%v section, unexpected error while parsing %v resource data: %v", curSectionName, hdr.Type, err)
						}
						return
					}
				}
			}
		}

		if err := p.End(); err != nil {
			if err == errInvalidOperation {
				t.Fatalf("p.End(): unexpected error: %v", err)
			}
			return
		}
	})
}
