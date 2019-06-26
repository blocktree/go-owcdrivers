package moacchainTransaction

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
)

func getLengthBytes(len int) []byte {
	return []byte{byte(len + 0x80)}
}

func getUint64Bytes(data uint64) []byte {
	if data == 0x00 {
		return []byte{0x80}
	} else if data < 0x80 {
		return []byte{byte(data)}
	}

	bytes := make([]byte, 8)
	binary.BigEndian.PutUint64(bytes, data)
	index := 0
	for _, b := range bytes {
		if b == 0 {
			index++
		} else {
			break
		}
	}

	return append(getLengthBytes(8-index), bytes[index:]...)
}

func getBigIntBytes(data *big.Int) []byte {
	ret := data.Bytes()

	return append(getLengthBytes(len(ret)), ret...)
}

func getHeadBytes(smalTag, largeTag byte, size uint64) []byte {
	if size < 56 {
		return []byte{smalTag + byte(size)}
	}
	ret := make([]byte, 9)
	sizesize := putint(ret[1:], size)
	ret[0] = largeTag + byte(sizesize)
	return ret[:sizesize+1]
}

func putint(b []byte, i uint64) (size int) {
	switch {
	case i < (1 << 8):
		b[0] = byte(i)
		return 1
	case i < (1 << 16):
		b[0] = byte(i >> 8)
		b[1] = byte(i)
		return 2
	case i < (1 << 24):
		b[0] = byte(i >> 16)
		b[1] = byte(i >> 8)
		b[2] = byte(i)
		return 3
	case i < (1 << 32):
		b[0] = byte(i >> 24)
		b[1] = byte(i >> 16)
		b[2] = byte(i >> 8)
		b[3] = byte(i)
		return 4
	case i < (1 << 40):
		b[0] = byte(i >> 32)
		b[1] = byte(i >> 24)
		b[2] = byte(i >> 16)
		b[3] = byte(i >> 8)
		b[4] = byte(i)
		return 5
	case i < (1 << 48):
		b[0] = byte(i >> 40)
		b[1] = byte(i >> 32)
		b[2] = byte(i >> 24)
		b[3] = byte(i >> 16)
		b[4] = byte(i >> 8)
		b[5] = byte(i)
		return 6
	case i < (1 << 56):
		b[0] = byte(i >> 48)
		b[1] = byte(i >> 40)
		b[2] = byte(i >> 32)
		b[3] = byte(i >> 24)
		b[4] = byte(i >> 16)
		b[5] = byte(i >> 8)
		b[6] = byte(i)
		return 7
	default:
		b[0] = byte(i >> 56)
		b[1] = byte(i >> 48)
		b[2] = byte(i >> 40)
		b[3] = byte(i >> 32)
		b[4] = byte(i >> 24)
		b[5] = byte(i >> 16)
		b[6] = byte(i >> 8)
		b[7] = byte(i)
		return 8
	}
}

func getAddressHashBytes(address string) ([]byte, error) {
	if address[:2] != "0x" {
		return nil, errors.New("Invalid address!")
	}
	hash, err := hex.DecodeString(address[2:])
	if err != nil || len(hash) != 20 {
		return nil, errors.New("Invalid address!")
	}

	return append(getLengthBytes(20), hash...), nil
}
