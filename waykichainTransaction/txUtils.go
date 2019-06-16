package waykichainTransaction

import (
	"regexp"
)

func sizeofVarInt(value int64) int {
	ret := 0
	n := value

	for {
		ret++
		if n <= 0x7f {
			break
		}
		n = (n >> 7) - 1
	}

	return ret
}

func reverseBytes(data []byte) []byte {
	ret := make([]byte, len(data))
	for index := 0; index < len(data); index++ {
		ret[index] = data[len(data)-1-index]
	}
	return ret
}

func int64ToUvarint(value int64) []byte {
	size := sizeofVarInt(value)
	tmp := make([]byte, ((size*8 + 6) / 7))
	len := 0
	n := value
	for {
		h := byte(0)
		if len == 0 {
			h = 0x00
		} else {
			h = 0x80
		}

		tmp[len] = byte((byte(n) & 0x7f) | h)

		if n <= 0x7f {
			break
		}

		n = (n >> 7) - 1
		len++
	}
	return reverseBytes(tmp[:size])
}

func isRegIdStr(regId string) bool {
	re := regexp.MustCompile(`^\s*(\d+)\-(\d+)\s*$`)
	return re.MatchString(regId)
}
