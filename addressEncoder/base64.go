package addressEncoder
import (
	"encoding/binary"
	"strconv"
)
const (
	StdPadding rune = '=' // Standard padding character
	NoPadding  rune = -1  // No padding
)
type Encoding struct {
	encode    []byte
	decodeMap [257]byte
	padChar   rune
	strict    bool
}

// NewEncoding returns a new padded Encoding defined by the given alphabet,
// which must be a 64-byte string that does not contain the padding character
// or CR / LF ('\r', '\n').
// The resulting Encoding uses the default padding character ('='),
// which may be changed or disabled via WithPadding.
func NewEncoding(encoder string) *Encoding {
	if len(encoder) != 64 {
		panic("encoding alphabet is not 64-bytes long")
	}
	for i := 0; i < len(encoder); i++ {
		if encoder[i] == '\n' || encoder[i] == '\r' {
			panic("encoding alphabet contains newline character")
		}
	}

	e := new(Encoding)
	e.padChar = StdPadding
	copy(e.encode[:], encoder)

	for i := 0; i < len(e.decodeMap); i++ {
		e.decodeMap[i] = 0xFF
	}
	for i := 0; i < len(encoder); i++ {
		e.decodeMap[encoder[i]] = byte(i)
	}
	return e
}

func (enc *Encoding) EncodedLen(n int) int {
	if enc.padChar == NoPadding {
		return (n*8 + 5) / 6 // minimum # chars at 6 bits per char
	}
	return (n + 2) / 3 * 4 // minimum # 4-char quanta, 3 bytes each
}

func (enc *Encoding) DecodedLen(n int) int {
	if enc.padChar == NoPadding {
		// Unpadded data may end with partial block of 2-3 characters.
		return n * 6 / 8
	}
	// Padded base64 should always be a multiple of 4 characters in length.
	return n / 4 * 3
}

func (enc *Encoding) Encode(dst, src []byte) {
	if len(src) == 0 {
		return
	}

	di, si := 0, 0
	n := (len(src) / 3) * 3
	for si < n {
		// Convert 3x 8bit source bytes into 4 bytes
		val := uint(src[si+0])<<16 | uint(src[si+1])<<8 | uint(src[si+2])

		dst[di+0] = enc.encode[val>>18&0x3F]
		dst[di+1] = enc.encode[val>>12&0x3F]
		dst[di+2] = enc.encode[val>>6&0x3F]
		dst[di+3] = enc.encode[val&0x3F]

		si += 3
		di += 4
	}

	remain := len(src) - si
	if remain == 0 {
		return
	}
	// Add the remaining small block
	val := uint(src[si+0]) << 16
	if remain == 2 {
		val |= uint(src[si+1]) << 8
	}

	dst[di+0] = enc.encode[val>>18&0x3F]
	dst[di+1] = enc.encode[val>>12&0x3F]

	switch remain {
	case 2:
		dst[di+2] = enc.encode[val>>6&0x3F]
		if enc.padChar != NoPadding {
			dst[di+3] = byte(enc.padChar)
		}
	case 1:
		if enc.padChar != NoPadding {
			dst[di+2] = byte(enc.padChar)
			dst[di+3] = byte(enc.padChar)
		}
	}
}

func (enc *Encoding) decode32(src []byte) (dn uint32, ok bool) {
	var n uint32
	_ = src[3]
	if n = uint32(enc.decodeMap[src[0]]); n == 0xff {
		return 0, false
	}
	dn |= n << 26
	if n = uint32(enc.decodeMap[src[1]]); n == 0xff {
		return 0, false
	}
	dn |= n << 20
	if n = uint32(enc.decodeMap[src[2]]); n == 0xff {
		return 0, false
	}
	dn |= n << 14
	if n = uint32(enc.decodeMap[src[3]]); n == 0xff {
		return 0, false
	}
	dn |= n << 8
	return dn, true
}

func (enc *Encoding) decode64(src []byte) (dn uint64, ok bool) {
	var n uint64
	_ = src[7]
	if n = uint64(enc.decodeMap[src[0]]); n == 0xff {
		return 0, false
	}
	dn |= n << 58
	if n = uint64(enc.decodeMap[src[1]]); n == 0xff {
		return 0, false
	}
	dn |= n << 52
	if n = uint64(enc.decodeMap[src[2]]); n == 0xff {
		return 0, false
	}
	dn |= n << 46
	if n = uint64(enc.decodeMap[src[3]]); n == 0xff {
		return 0, false
	}
	dn |= n << 40
	if n = uint64(enc.decodeMap[src[4]]); n == 0xff {
		return 0, false
	}
	dn |= n << 34
	if n = uint64(enc.decodeMap[src[5]]); n == 0xff {
		return 0, false
	}
	dn |= n << 28
	if n = uint64(enc.decodeMap[src[6]]); n == 0xff {
		return 0, false
	}
	dn |= n << 22
	if n = uint64(enc.decodeMap[src[7]]); n == 0xff {
		return 0, false
	}
	dn |= n << 16
	return dn, true
}

type CorruptInputError int64

func (e CorruptInputError) Error() string {
	return "illegal base64 data at input byte " + strconv.FormatInt(int64(e), 10)
}

func (enc *Encoding) decodeQuantum(dst, src []byte, si int) (nsi, n int, err error) {
	// Decode quantum using the base64 alphabet
	var dbuf [4]byte
	dinc, dlen := 3, 4

	for j := 0; j < len(dbuf); j++ {
		if len(src) == si {
			switch {
			case j == 0:
				return si, 0, nil
			case j == 1, enc.padChar != NoPadding:
				return si, 0, CorruptInputError(si - j)
			}
			dinc, dlen = j-1, j
			break
		}
		in := src[si]
		si++

		out := enc.decodeMap[in]
		if out != 0xff {
			dbuf[j] = out
			continue
		}

		if in == '\n' || in == '\r' {
			j--
			continue
		}

		if rune(in) != enc.padChar {
			return si, 0, CorruptInputError(si - 1)
		}

		// We've reached the end and there's padding
		switch j {
		case 0, 1:
			// incorrect padding
			return si, 0, CorruptInputError(si - 1)
		case 2:
			// "==" is expected, the first "=" is already consumed.
			// skip over newlines
			for si < len(src) && (src[si] == '\n' || src[si] == '\r') {
				si++
			}
			if si == len(src) {
				// not enough padding
				return si, 0, CorruptInputError(len(src))
			}
			if rune(src[si]) != enc.padChar {
				// incorrect padding
				return si, 0, CorruptInputError(si - 1)
			}

			si++
		}

		// skip over newlines
		for si < len(src) && (src[si] == '\n' || src[si] == '\r') {
			si++
		}
		if si < len(src) {
			// trailing garbage
			err = CorruptInputError(si)
		}
		dinc, dlen = 3, j
		break
	}

	// Convert 4x 6bit source bytes into 3 bytes
	val := uint(dbuf[0])<<18 | uint(dbuf[1])<<12 | uint(dbuf[2])<<6 | uint(dbuf[3])
	dbuf[2], dbuf[1], dbuf[0] = byte(val>>0), byte(val>>8), byte(val>>16)
	switch dlen {
	case 4:
		dst[2] = dbuf[2]
		dbuf[2] = 0
		fallthrough
	case 3:
		dst[1] = dbuf[1]
		if enc.strict && dbuf[2] != 0 {
			return si, 0, CorruptInputError(si - 1)
		}
		dbuf[1] = 0
		fallthrough
	case 2:
		dst[0] = dbuf[0]
		if enc.strict && (dbuf[1] != 0 || dbuf[2] != 0) {
			return si, 0, CorruptInputError(si - 2)
		}
	}
	dst = dst[dinc:]

	return si, dlen - 1, err
}

func (enc *Encoding) Decode(dst, src []byte) (n int, err error) {
	if len(src) == 0 {
		return 0, nil
	}

	si := 0
	for strconv.IntSize >= 64 && len(src)-si >= 8 && len(dst)-n >= 8 {
		if dn, ok := enc.decode64(src[si:]); ok {
			binary.BigEndian.PutUint64(dst[n:], dn)
			n += 6
			si += 8
		} else {
			var ninc int
			si, ninc, err = enc.decodeQuantum(dst[n:], src, si)
			n += ninc
			if err != nil {
				return n, err
			}
		}
	}

	for len(src)-si >= 4 && len(dst)-n >= 4 {
		if dn, ok := enc.decode32(src[si:]); ok {
			binary.BigEndian.PutUint32(dst[n:], dn)
			n += 3
			si += 4
		} else {
			var ninc int
			si, ninc, err = enc.decodeQuantum(dst[n:], src, si)
			n += ninc
			if err != nil {
				return n, err
			}
		}
	}

	for si < len(src) {
		var ninc int
		si, ninc, err = enc.decodeQuantum(dst[n:], src, si)
		n += ninc
		if err != nil {
			return n, err
		}
	}
	return n, err
}
func (enc *Encoding) Base64Encode(src []byte) string {
	buf := make([]byte, enc.EncodedLen(len(src)))
	enc.Encode(buf, src)
	return string(buf)
}


func (enc *Encoding) Base64Decode(s string) ([]byte, error) {

	enc=NewEncoding(string(enc.encode))
	dbuf := make([]byte, enc.DecodedLen(len(s)))
	n, err := enc.Decode(dbuf, []byte(s))
	return dbuf[:n], err
}