package dnsmsg

import (
	"bytes"
	"testing"
)

func TestTSIG(t *testing.T) {
	b := StartBuilder(make([]byte, 0, 512), 0, 0)
	b.Question(Question[RawName]{
		Name:  MustNewRawName("example.com"),
		Type:  TypeA,
		Class: ClassIN,
	})
	expect := bytes.Clone(b.Bytes())
	b.StartAnswers()
	for i := 0; i < 2; i++ {
		b.ResourceA(ResourceHeader[RawName]{
			Name:  MustNewRawName("example.com"),
			Type:  TypeA,
			Class: ClassIN,
			TTL:   3600,
		}, ResourceA{A: [4]byte{192, 9, 2, 1}})
	}

	p, _, err := Parse(b.Bytes())
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}

	if _, err = p.Question(); err != nil {
		t.Fatalf("p.Question() unexpected error: %v", err)
	}

	var bbuf bytes.Buffer
	p.TruncatedMSG().WriteMessage(&bbuf)
	got := bbuf.Bytes()
	if !bytes.Equal(got, expect) {
		t.Fatalf("p.TruncatedMSG().WriteMessage() = %v, want: %v", got, expect)
	}
}
