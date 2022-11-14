package dnsmsg

import "testing"

func TestBuilderAutoCompress(t *testing.T) {
	b := NewBuilder(make([]byte, 0, 512))

	acm := CompressionNameBuilder{m: map[string]uint16{}}
	b.ResourceHeader(&ResourceHeader[BuilderName]{
		Name:  acm.NewStringName("go.dev."),
		Type:  TypeSOA,
		Class: ClassIN,
		TTL:   100,
	})

	b.ResourceThreeNames(&ResourceThreeNames{
		A: acm.NewStringName("ns1.go.dev."),
		B: acm.NewStringName("admin.ns1.go.dev."),
		C: acm.NewStringName("adam.ns1.go.dev."),
	})
	msg := b.Finish()
	t.Log(msg)

	p, _ := NewParser(msg)
	hdr, err := p.ResourceHeader()
	t.Log(hdr.Name.String(), err)

	name, err := p.Name()
	t.Log(name.String(), err, name.lenNoPtr, name.rawLen)
	name, err = p.Name()
	t.Log(name.String(), err, name.lenNoPtr, name.rawLen)
	name, err = p.Name()
	t.Log(name.String(), err, name.lenNoPtr, name.rawLen)
}

func TestBuilder(t *testing.T) {
	b := NewBuilder(make([]byte, 0, 512))

	res := ResourceHeader[BuilderName]{
		Name:  NewStringName("go.dev"),
		Type:  TypeSOA,
		Class: ClassIN,
		TTL:   100,
	}
	b.ResourceHeader(&res)

	off := res.Name.MsgOffset()

	threeRes := ResourceThreeNames{}
	threeRes.A = NewRawNameWithPtr([]byte{3, 'n', 's', '1'}, off)
	threeRes.B = NewRawNamePtrTo([]byte{5, 'a', 'd', 'm', 'i', 'n'}, &threeRes.A, 0)
	threeRes.C = NewRawNamePtrTo([]byte{4, 'a', 'd', 'a', 'm'}, &threeRes.A, 0)

	b.ResourceThreeNames(&threeRes)
	msg := b.Finish()

	p, _ := NewParser(msg)
	hdr, err := p.ResourceHeader()
	t.Log(hdr.Name.String(), err)

	name, err := p.Name()
	t.Log(name.String(), err)
	name, err = p.Name()
	t.Log(name.String(), err)
	name, err = p.Name()
	t.Log(name.String(), err)
}

func BenchmarkBuilderCompressionHardManual(b *testing.B) {
	gBuf := make([]byte, 0, 128)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := append(gBuf[:0:128], []byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0}...)
		buf = appendUint16(buf, uint16(TypeSOA))
		buf = appendUint16(buf, uint16(ClassIN))
		buf = appendUint32(buf, 100)
		buf = appendUint16(buf, 0)

		l := len(buf)
		buf = append(buf, []byte{3, 'n', 's', '1'}...)
		buf = appendUint16(buf, 0|0xC000)

		buf = append(buf, []byte{5, 'a', 'd', 'm', 'i', 'n'}...)
		buf = appendUint16(buf, 0xC000|uint16(l))

		buf = append(buf, []byte{4, 'a', 'd', 'a', 'm'}...)
		buf = appendUint16(buf, 0xC000|uint16(l))

		gBuf = buf
	}
}

func BenchmarkBuilderCompressionHard(b *testing.B) {
	buf := make([]byte, 0, 128)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b := NewBuilder(buf[:0:128])

		res := ResourceHeader[BuilderName]{
			Name:  NewRawName([]byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0}),
			Type:  TypeSOA,
			Class: ClassIN,
			TTL:   100,
		}
		b.ResourceHeader(&res)
		off := res.Name.MsgOffset()

		threeRes := ResourceThreeNames{}
		threeRes.A = NewRawNameWithPtr([]byte{3, 'n', 's', '1'}, off)
		threeRes.B = NewRawNamePtrTo([]byte{5, 'a', 'd', 'm', 'i', 'n'}, &threeRes.A, 0)
		threeRes.C = NewRawNamePtrTo([]byte{4, 'a', 'd', 'a', 'm'}, &threeRes.A, 0)
		b.ResourceThreeNames(&threeRes)

		buf = b.Finish()
	}
}

func BenchmarkBuilderCompressionHardAutoCompress(b *testing.B) {
	buf := make([]byte, 0, 128)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b := NewBuilder(buf[:0:128])
		acm := CompressionNameBuilder{m: map[string]uint16{}}
		b.ResourceHeader(&ResourceHeader[BuilderName]{
			Name:  acm.NewStringName("go.dev."),
			Type:  TypeSOA,
			Class: ClassIN,
			TTL:   100,
		})

		b.ResourceThreeNames(&ResourceThreeNames{
			A: acm.NewStringName("ns1.go.dev."),
			B: acm.NewStringName("admin.ns1.go.dev."),
			C: acm.NewStringName("adam.ns1.go.dev."),
		})

		buf = b.Finish()
	}
}

func BenchmarkBuilderHardAResources(b *testing.B) {
	buf := make([]byte, 0, 1024*2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b := NewBuilder(buf[: 0 : 2*1024])

		res := Question[BuilderName]{
			Name:  NewRawName([]byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0}),
			Type:  TypeSOA,
			Class: ClassIN,
		}
		b.Question(&res)

		for i := uint8(0); i < 4; i++ {
			b.ResourceHeader(&ResourceHeader[BuilderName]{
				Name:   NewPtrName(res.Name.MsgOffset()),
				Type:   TypeA,
				Class:  ClassIN,
				TTL:    128,
				Length: 4,
			})
			b.ResourceA(ResourceA{A: [4]byte{1, 1, 1, i}})
		}

		buf = b.Finish()
	}
}

/*
func BenchmarkRawDomain(b *testing.B) {
	buf := make([]byte, 0, 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n := []byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0}
		strName := "go.dev"
		bytesStrName := []byte("go.dev")

		b := NewBuilder(buf[:0:1024])
		b.Name(NewRawName(n))
		b.Name(NewStringName(strName))
		b.Name(NewBytesName(bytesStrName))
		buf = b.Finish()
	}
}

func BenchmarkRawDomainRR(b *testing.B) {
	buf := make([]byte, 0, 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n := []byte{2, 'g', 'o', 3, 'd', 'e', 'v', 0}
		b := NewBuilder(buf[:0:1024])
		b.ResHdr(ResourceHeader[BuilderName]{
			Name: NewRawName(n),
		})
		buf = b.Finish()
	}
}
*/
