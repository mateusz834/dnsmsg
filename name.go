package dnsmsg

import "strings"

type Compression uint8

func (c Compression) canCompress(compressionBuilder bool) bool {
	if !compressionBuilder || c == CompressionNever {
		return false
	}
	return true
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
