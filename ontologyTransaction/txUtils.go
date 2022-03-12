package ontologyTransaction

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
)

//reverseBytes endian reverse
func reverseBytes(s []byte) []byte {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}

//reverseHexToBytes decode a hex string to an byte array,then change the endian
func reverseHexToBytes(hexVar string) ([]byte, error) {
	if len(hexVar)%2 == 1 {
		return nil, errors.New("Invalid TxHash!")
	}
	ret, err := hex.DecodeString(hexVar)
	if err != nil {
		return nil, err
	}
	return reverseBytes(ret), nil
}

//reverseBytesToHex change the endian of the input byte array then encode it to hex string
func reverseBytesToHex(bytesVar []byte) string {
	return hex.EncodeToString(reverseBytes(bytesVar))
}

//uint16ToLittleEndianBytes
func uint16ToLittleEndianBytes(data uint16) []byte {
	tmp := [2]byte{}
	binary.LittleEndian.PutUint16(tmp[:], data)
	return tmp[:]
}

//littleEndianBytesToUint16
func littleEndianBytesToUint16(data []byte) uint16 {
	return binary.LittleEndian.Uint16(data)
}

//uint32ToLittleEndianBytes
func uint32ToLittleEndianBytes(data uint32) []byte {
	tmp := [4]byte{}
	binary.LittleEndian.PutUint32(tmp[:], data)
	return tmp[:]
}

//littleEndianBytesToUint32
func littleEndianBytesToUint32(data []byte) uint32 {
	return binary.LittleEndian.Uint32(data)
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

func bytesReverse(u []byte) []byte {
	for i, j := 0, len(u)-1; i < j; i, j = i+1, j-1 {
		u[i], u[j] = u[j], u[i]
	}
	return u
}

func getLength(l int) []byte {
	if l < PushBytes75 {
		return []byte{byte(l)}
	} else if l < 0x100 {
		return []byte{PushData1, byte(l)}
	} else if l < 0x10000 {
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, uint16(l))
		return append([]byte{byte(PushData2)}, b...)
	} else {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, uint32(l))
		return append([]byte{byte(PushData4)}, b...)
	}
}

var bigOne = big.NewInt(1)

func bigIntToNeoBytes(data *big.Int) []byte {
	bs := data.Bytes()
	if len(bs) == 0 {
		return []byte{}
	}
	b := bs[0]
	if data.Sign() < 0 {
		for i, b := range bs {
			bs[i] = ^b
		}
		temp := big.NewInt(0)
		temp.SetBytes(bs)
		temp.Add(temp, bigOne)
		bs = temp.Bytes()
		bytesReverse(bs)
		if b>>7 == 0 {
			bs = append(bs, 255)
		}
	} else {
		bytesReverse(bs)
		if b>>7 == 1 {
			bs = append(bs, 0)
		}
	}
	return append(getLength(len(bs)), bs...)
}

func uint64ToEmitBytes(data uint64) []byte {
	if data == 0 {
		return []byte{OpCodePush0}
	}
	if data > 0 && data < 16 {
		return []byte{OpCodePush1 - 1 + byte(data)}
	}

	val := big.NewInt(0)
	val.SetUint64(data)
	return bigIntToNeoBytes(val)
}

func bigIntToEmitBytes(data *big.Int) []byte {
	if data.Cmp(big.NewInt(int64(-1))) == 0 {
		return []byte{OpCodePushM1}
	}
	if data.Sign() == 0 {
		return []byte{OpCodePush0}
	}

	if data.Cmp(big.NewInt(int64(0))) == 1 && data.Cmp(big.NewInt(int64(16))) == -1 {
		return []byte{OpCodePush1 - 1 + byte(data.Int64())}
	}

	return bigIntToNeoBytes(data)
}
