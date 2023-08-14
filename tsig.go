package dnsmsg

import (
	"io"
)

// TruncatedMSG creates a [FakeCountsMessage].
// The returned [FakeCountsMessage] contains all fully parsed questions and resources.
// The resource data must be parsed to be includes in the returned message, so when
// only the resource header was parsed then the resource is not included in the
// returned message.
func (p *Parser) TruncatedMSG() FakeCountsMessage {
	var counts [4]uint16
	copy(counts[:], p.counts[:p.curSection%4])
	counts[p.curSection%4] = p.counts[p.curSection%4] - p.remainingCurSectionCount
	rhdrLen := 0
	if p.rhdrNameLength != 0 {
		rhdrLen = 12 + int(p.rhdrNameLength)
	}
	return FakeCountsMessage{
		newCounts:            counts,
		oldMessage:           p.msg,
		newCountsMessageSize: p.curOffset - rhdrLen,
	}
}

type FakeCountsMessage struct {
	oldMessage           []byte
	newCountsMessageSize int
	newCounts            [4]uint16
}

func (t *FakeCountsMessage) header() (hdr [headerLen]byte) {
	copy(hdr[:4], t.oldMessage[:4])
	packUint16(hdr[4:6], t.newCounts[sectionQuestions])
	packUint16(hdr[6:8], t.newCounts[sectionAnswers])
	packUint16(hdr[8:10], t.newCounts[sectionAuthorities])
	packUint16(hdr[10:12], t.newCounts[sectionAdditionals])
	return
}

func (t FakeCountsMessage) Build() []byte {
	hdr := t.header()
	msg := make([]byte, t.newCountsMessageSize)
	copy(msg[headerLen:], t.oldMessage[headerLen:t.newCountsMessageSize])
	copy(msg[:headerLen], hdr[:])
	return msg
}

func (t FakeCountsMessage) Append(buf []byte) []byte {
	hdr := t.header()
	buf = append(buf, hdr[:]...)
	return append(buf, t.oldMessage[headerLen:t.newCountsMessageSize]...)
}

// // Truncate truncates the message up to this point of parsing, returns a byte slice
// // that represents a valid message with an updated DNS header and slice length.
// //
// // Note: It modifies the header of the message passed to the [Parse] function, the Parser is valid after truncation
// // of the message (the Parser, and all of its copies made before and after, are not truncated, they  can still parse all the remaining
// // resources, but the slice passed to [Parse] becomes an invalid DNS message.
func (t FakeCountsMessage) Update() []byte {
	hdr := t.header()
	copy(t.oldMessage, hdr[:])
	return t.oldMessage[:t.newCountsMessageSize]
}

func (t FakeCountsMessage) UpdateWithRollback() ([]byte, FakeCountsMessage) {
	var oldHdr Header
	oldHdr.unpack([headerLen]byte(t.oldMessage))

	newEncodedHdr := t.header()
	copy(t.oldMessage, newEncodedHdr[:])
	return t.oldMessage[:t.newCountsMessageSize], FakeCountsMessage{
		newCounts: [4]uint16{
			oldHdr.QDCount,
			oldHdr.ANCount,
			oldHdr.NSCount,
			oldHdr.ARCount,
		},
		oldMessage:           t.oldMessage,
		newCountsMessageSize: len(t.oldMessage),
	}
}

func (t *FakeCountsMessage) UpdateKeepOldCounts() []byte {
	var oldHdr Header
	oldHdr.unpack([headerLen]byte(t.oldMessage))
	t.newCounts = [4]uint16{
		oldHdr.QDCount,
		oldHdr.ANCount,
		oldHdr.NSCount,
		oldHdr.ARCount,
	}
	t.newCountsMessageSize = len(t.oldMessage)
	newEncodedHdr := t.header()
	copy(t.oldMessage, newEncodedHdr[:])
	return t.oldMessage[:t.newCountsMessageSize]
}

func (t FakeCountsMessage) Parse() (Header, Parser) {
	return Header{
			Flags:   Flags(unpackUint16(t.oldMessage[2:])),
			ID:      unpackUint16(t.oldMessage[0:]),
			QDCount: t.newCounts[sectionQuestions],
			ANCount: t.newCounts[sectionAnswers],
			NSCount: t.newCounts[sectionAuthorities],
			ARCount: t.newCounts[sectionAdditionals],
		}, Parser{
			msg:                      t.oldMessage[:t.newCountsMessageSize],
			curOffset:                headerLen,
			counts:                   t.newCounts,
			remainingCurSectionCount: t.newCounts[sectionQuestions],
		}
}

func (t FakeCountsMessage) EncodedHeader() [headerLen]byte {
	return t.header()
}

func (t FakeCountsMessage) MessageWithoutHeader() []byte {
	return t.oldMessage[headerLen:t.newCountsMessageSize]
}

func (t FakeCountsMessage) WriteMessage(w io.Writer) error {
	rawHdr := t.header()
	_, err := w.Write(rawHdr[:])
	if err != nil {
		return err
	}
	_, err = w.Write(t.MessageWithoutHeader())
	return err
}
