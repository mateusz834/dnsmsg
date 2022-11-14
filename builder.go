package dnsmsg

//TODO: reconsider the 2^16-1 (16bit) msg size in the entire package
//TODO: is there any vaid use case where msg can be > 16bits?? AXFR??

import "math"

type Builder struct {
	buf                    []byte
	lastResHdrLengthOffset uint16
}

func NewBuilder(buf []byte) Builder {
	return Builder{
		// The []byte passed to this function escapes
		// to heap because of golang/go#54563
		buf: buf,
	}
}

func (b *Builder) CurOffset() uint16 {
	//TODO: we can start NewBuilder with len != 0
	return uint16(len(b.buf))
}

func (b *Builder) Finish() (msg []byte) {
	msg = b.buf
	if len(msg) > math.MaxUint16 {
		msg = nil
	}
	b.buf = nil
	return msg
}

func (b *Builder) Question(hdr *Question[BuilderName]) error {
	b.Name(&hdr.Name)
	b.buf = appendUint16(b.buf, uint16(hdr.Type))
	b.buf = appendUint16(b.buf, uint16(hdr.Class))
	return nil
}

func (b *Builder) ResourceHeader(hdr *ResourceHeader[BuilderName]) error {
	b.Name(&hdr.Name)
	b.buf = appendUint16(b.buf, uint16(hdr.Type))
	b.buf = appendUint16(b.buf, uint16(hdr.Class))
	b.buf = appendUint32(b.buf, hdr.TTL)
	b.lastResHdrLengthOffset = uint16(len(b.buf))
	b.buf = appendUint16(b.buf, hdr.Length)
	return nil
}

func (b *Builder) ResourceHeaderFixupLength(length uint16) {
	packUint16(b.buf[b.lastResHdrLengthOffset:], length)
}

func (b *Builder) ResourceA(a ResourceA) {
	b.buf = append(b.buf, a.A[:]...)
}

type ResourceThreeNames struct {
	A, B, C BuilderName
}

func (b *Builder) ResourceThreeNames(soa *ResourceThreeNames) error {
	b.Name(&soa.A)
	b.Name(&soa.B)
	b.Name(&soa.C)
	return nil
}

func (b *Builder) ResourceSOA(soa ResourceSOA[BuilderName]) error {
	b.Name(&soa.NS)
	b.Name(&soa.Mbox)
	b.buf = appendUint32(b.buf, soa.Serial)
	b.buf = appendUint32(b.buf, soa.Refresh)
	b.buf = appendUint32(b.buf, soa.Retry)
	b.buf = appendUint32(b.buf, soa.Expire)
	b.buf = appendUint32(b.buf, soa.Minimum)
	return nil
}

/*
func (b *Builder) ResourceNS(ns ResourceNS[BuilderName]) error {
	b.Name(&ns.NS)
	return nil
}

func (b *Builder) ResourceCNAME(ns ResourceCNAME[BuilderName]) error {
	b.Name(&ns.CNAME)
	return nil
}

func (b *Builder) ResourcePTR(ptr ResourcePTR[BuilderName]) error {
	b.Name(&ptr.PTR)
	return nil
}
*/
/*

func (b *Builder) ResourceMX(mx ResourceMX[BuilderName]) error {
	b.buf = appendUint16(b.buf, mx.Pref)
	b.Name(&mx.MX)
	return nil
}

func (b *Builder) ResourceTXT(mx ResourceTXT) {
	b.buf = append(b.buf, mx.TXT...)
}

func (b *Builder) ResourceAAAA(aaaa ResourceAAAA) {
	b.buf = append(b.buf, aaaa.AAAA[:]...)
}
*/
