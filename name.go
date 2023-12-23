package dnsmsg

import "strings"

const (
	maxEncodedNameLen = 255
	maxLabelLength    = 63
)

type Compression uint8

func (c Compression) canCompress(builderAllowsCompression bool) bool {
	return builderAllowsCompression && c != CompressionNever
}

const (
	CompressionWhenPossible Compression = 0 // compress when RFC permits compression
	CompressionNever        Compression = 1 // never compress

	CompressionNotCompressed Compression = 128 // name was not compressed
	CompressionCompressed    Compression = 64  // name was compressed
)

type NName struct {
	// Name is non-comparable to prevent possible mistakes, DNS names should
	// be compared in a case-insensitive way, and the Compression field might
	// not be equal for the same names.
	_ [0]func()

	Name   [255]byte
	Length uint8

	// When [Name] is used with a [Builder], the field should be set to
	//   - [CompressionWhenPossible] - (default, zero value) name will be compressed
	//     when the RFC permits compression
	//   - [CompressionNever] - name will never be compressed
	//
	// [Parser] produces [Name]s with:
	//   - [CompressonNotCompressed] - name used DNS compression
	//   - [CompressionCompressed] -  name did not use DNS compression
	//
	// [Builder] also permits [Name]s producted by the [Parser] with this field set to
	// [CompressionNotCompressed] or [CompressionCompressed], it treats them as [CompressionWhenPossible].
	//
	// This field should only be set to the constants mentioned before.
	Compression Compression
}

func ParseName(name string) (NName, error) {
	if name == "" {
		return NName{}, errInvalidName
	}

	if name == "." {
		return NName{Length: 1}, nil
	}

	var n NName
	n.Length = 1

	labelLengthIndex := 0
	rooted := false

	for i := 0; i < len(name); i++ {
		char := name[i]
		rooted = false

		labelLength := n.Length - uint8(labelLengthIndex) - 1
		if labelLength > maxLabelLength {
			return NName{}, errInvalidName
		}

		if n.Length == maxEncodedNameLen {
			return NName{}, errInvalidName
		}

		switch char {
		case '.':
			rooted = true
			if labelLength == 0 {
				return NName{}, errInvalidName
			}
			n.Name[labelLengthIndex] = labelLength
			labelLengthIndex = int(n.Length)
			n.Length++
		case '\\':
			if len(name) == i+1 {
				return NName{}, errInvalidName
			}
			i++
			if isDigit(name[i]) {
				if len(name[i:]) < 3 || !isDigit(name[i+1]) || !isDigit(name[i+2]) {
					return NName{}, errInvalidName
				}
				dddChar, ok := decodeDDD([3]byte([]byte(name[i:])))
				if !ok {
					return NName{}, errInvalidName
				}
				i += 2
				n.Name[n.Length] = dddChar
				n.Length++
				continue
			}
			n.Name[n.Length] = name[i]
			n.Length++
		default:
			n.Name[n.Length] = char
			n.Length++
		}
	}

	if !rooted {
		if n.Length == maxEncodedNameLen {
			return NName{}, errInvalidName
		}
		labelLength := n.Length - uint8(labelLengthIndex) - 1
		if labelLength > maxLabelLength {
			return NName{}, errInvalidName
		}
		n.Name[labelLengthIndex] = labelLength
		n.Length++
	}

	return n, nil
}

func MustParseName(name string) NName {
	n, err := ParseName(name)
	if err != nil {
		panic("dnsmsg: MustParseName: " + err.Error())
	}
	return n
}

func (n *NName) String() string {
	if n.Length == 0 {
		return ""
	}

	if n.Length == 1 {
		return "."
	}

	var b strings.Builder
	b.Grow(int(n.Length))

	i := 0
	for {
		labelLength := int(n.Name[i])
		if labelLength == 0 {
			break
		}
		i += 1
		for _, v := range n.Name[i : i+labelLength] {
			switch {
			case v == '.':
				b.WriteString("\\.")
			case v == '\\':
				b.WriteString("\\\\")
			case v < '!' || v > '~':
				b.WriteByte('\\')
				b.Write(toASCIIDecimal(v))
			default:
				b.WriteByte(v)
			}
		}
		b.WriteString(".")
		i += labelLength
	}

	return b.String()
}

// Equal return true when n and other represents the same name (case-insensitively).
func (n *NName) Equal(other *NName) bool {
	// Label Lengths are limited to 63, ASCII letters start at 65, so we can
	// use this for our benefit and not iterate over labels separately.
	return n.Length == other.Length && caseInsensitiveEqual(n.Name[:n.Length], other.Name[:other.Length])
}

// len(a) must be equal to len(b)
func caseInsensitiveEqual(a []byte, b []byte) bool {
	for i := 0; i < len(a); i++ {
		if !equalASCIICaseInsensitive(a[i], b[i]) {
			return false
		}
	}
	return true
}

func equalASCIICaseInsensitive(a, b byte) bool {
	const caseDiff = 'a' - 'A'

	if a >= 'a' && a <= 'z' {
		a -= caseDiff
	}

	if b >= 'a' && b <= 'z' {
		b -= caseDiff
	}

	return a == b
}

// ptrLoopCount represents an upper limit of pointers that we
// accept in a single DNS name.
// There is still a poosibilitty of a false positive here, but only for names
// that are badly compressed (pointer to a pointer, pointer to a root name).
const ptrLoopCount = ((maxEncodedNameLen - 1) / 2)

func (n *NName) unpack(msg []byte, nameStart int) (uint16, error) {
	var (
		// length of the raw name, without compression pointers.
		rawNameLen = uint16(0)

		// message offset, length up to the first compression pointer (if any, including it).
		offset = uint16(0)

		ptrCount = uint8(0)
	)

	n.Compression = CompressionNotCompressed
	for i := nameStart; i < len(msg); {
		// Compression pointer
		if msg[i]&0xC0 == 0xC0 {
			if ptrCount++; ptrCount > ptrLoopCount {
				return 0, errPtrLoop
			}

			if offset == 0 {
				offset = rawNameLen + 2
			}

			// Compression pointer is 2 bytes long.
			if len(msg) == int(i)+1 {
				return 0, errInvalidDNSName
			}

			i = int(uint16(msg[i]^0xC0)<<8 | uint16(msg[i+1]))
			n.Compression = CompressionCompressed
			continue
		}

		// Two leading bits are reserved, except for compression pointer (above).
		if msg[i]&0xC0 != 0 {
			return 0, errInvalidDNSName
		}

		if int(msg[i]) > len(msg[i+1:]) {
			return 0, errInvalidDNSName
		}

		copy(n.Name[rawNameLen:], msg[i:i+1+int(msg[i])])

		if rawNameLen++; rawNameLen > maxEncodedNameLen {
			return 0, errInvalidDNSName
		}

		if msg[i] == 0 {
			if offset == 0 {
				offset = rawNameLen
			}
			n.Length = uint8(rawNameLen)
			return offset, nil
		}

		rawNameLen += uint16(msg[i])
		i += int(msg[i]) + 1
	}

	return 0, errInvalidDNSName
}
