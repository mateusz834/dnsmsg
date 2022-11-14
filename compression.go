package dnsmsg

func hashRawName(r []byte) (hash uint8) {
	for i := 0; i < len(r); i += int(r[i]) + 1 {
		for j := i + 1; j < i+1+int(r[i]); j++ {
			hash ^= r[j]
		}
	}
	return hash
}

func hashRawNameWithPtrs(msg []byte, r []byte, ptr uint16) (hash uint8) {
	hash = hashRawName(r)
	return hash
}

type hashEntry struct {
	fullHash uint8
	ptr      uint16
}

type hashBucket struct {
	length  uint8
	entries [4]hashEntry
}

type hashMap struct {
	m [10]hashBucket
}

func (h *hashMap) compress(msg []byte, r []byte) ([]byte, uint16) {
	for i := 0; i < len(r); i += int(r[i]) + 1 {
		raw := r[i:]
		hash := hashRawName(raw)

		bucket := &h.m[hash%uint8(len(h.m))]

		for j := uint8(0); j < bucket.length; j++ {
			// potential candidate
			if bucket.entries[j].fullHash == hash {
				ptr := bucket.entries[j].ptr
				if len(msg) <= int(ptr) {
					continue
				}

				if equalRaw(msg, ptr, raw) {
					return r[:i], ptr
				}
			}
		}

		if int(bucket.length) == len(bucket.entries) {
			panic("would overflow")
		}

		bucket.entries[bucket.length].fullHash = hash
		bucket.entries[bucket.length].ptr = uint16(len(msg) + i)
		bucket.length++
	}

	return r, ^uint16(0)
}

func equalRaw(msg []byte, im1 uint16, raw []byte) bool {
	im2 := uint16(0)

	for {
		// Resolve all (in a row) compression pointers of m
		for msg[im1]&0xC0 == 0xC0 {
			im1 = uint16(msg[im1]^0xC0)<<8 | uint16(msg[im1+1])
		}

		if len(raw) <= int(im2) {
			return false
		}

		// different label lengths
		if msg[im1] != raw[im2] {
			return false
		}

		if msg[im1] == 0 {
			return true
		}

		if uint16(len(raw[im2:])) < uint16(raw[im2])+1 {
			return false
		}

		if !equal(msg[im1+1:im1+1+uint16(msg[im1])], raw[im2+1:im2+1+uint16(raw[im2])]) {
			return false
		}

		im1 += uint16(msg[im1]) + 1
		im2 += uint16(raw[im2]) + 1
	}
}

type AutoCompressBuilder struct {
	buf []byte
}
