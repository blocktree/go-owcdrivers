package bytomTransaction

import (
	"encoding/binary"
)

func uint64ToUvarint(x uint64) []byte {
	ret := [8]byte{}

	len := binary.PutUvarint(ret[:], x)

	if len == 0 {
		return nil
	}
	return ret[:len]
}

func uvarintToUint64(buf []byte) uint64 {
	if buf == nil || len(buf) == 0x00 {
		return 0
	}

	ret, length := binary.Uvarint(buf)

	if length != len(buf) {
		return 0
	}

	return ret
}

//uint64ToLittleEndianBytes
func uint64ToLittleEndianBytes(data uint64) []byte {
	tmp := [8]byte{}
	binary.LittleEndian.PutUint64(tmp[:], data)
	return tmp[:]
}

//littleEndianBytesToUint64
func littleEndianBytesToUint64(data []byte) uint64 {
	return binary.LittleEndian.Uint64(data)
}
