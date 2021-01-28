package polkadotTransaction

import (
	"encoding/binary"
	"encoding/hex"
)

func CompactLength(data uint32) int {
	if data >=0 && data <= singleModeMaxValue {
		return 1
	} else if data <= twoByteModeMaxValue {
		return 2
	} else if data <= fourByteModeMaxValue {
		return 4
	} else {
		return 5
	}
}

func ExtendLEBytes(input []byte, length int) []byte {
	diff := length - len(input)
	if diff == 0 {
		return input
	}
	for i := 0; i < diff; i++ {
		input = append(input, 0)
	}
	return input
}

//uint32ToLittleEndianBytes
func uint32ToLittleEndianBytes(data uint32) []byte {
	tmp := [4]byte{}
	binary.LittleEndian.PutUint32(tmp[:], data)
	return tmp[:]
}

func removeExtraLEBytes(input []byte) []byte {
	index := len(input)
	for {
		if input[index-1] != 0 {
			break
		} else {
			index--
		}
	}
	return input[:index]
}

func BytesToCompactBytes(bytes []byte) (res []byte) {
	lenOfBytes := len(bytes)
	if lenOfBytes > 4 {
		zeroByte := len(bytes) - 4
		zeroByte = zeroByte << modeBits
		zeroByte |= int(bigIntMode)

		res = []byte{byte(zeroByte)}
		res = append(res, bytes...)
	} else {
		mode := fourByteMode

		switch lenOfBytes {
		case 1:
			mode = singleMode
		case 2:
			mode = twoByteMode
		}

		var nextRepl byte
		for i := range bytes {
			repl := bytes[i] & 192
			repl = repl >> 6
			bytes[i] = bytes[i] << modeBits
			if i != 0 {
				bytes[i] |= nextRepl
			}
			nextRepl = repl
		}
		if nextRepl != 0 {
			bytes = append(bytes, nextRepl)
		}
		bytes[0] |= mode
		bytes = ExtendLEBytes(bytes, int(modeToNumOfBytes[mode]))

		res = bytes
	}
	return
}

func Encode(data uint32) string {
	if data > fourByteModeMaxValue {
		return "03" + hex.EncodeToString(uint32ToLittleEndianBytes(data))
	}
	bytes := uint32ToLittleEndianBytes(data)
	bytes = removeExtraLEBytes(bytes)
	compactLength := CompactLength(data)
	length := len(bytes)
	if length < compactLength {
		for i := 0; i < compactLength- length; i ++ {
			bytes = append(bytes, 0)
		}
	}

	ret := BytesToCompactBytes(bytes)
	if compactLength == 5 {
		ret[0] = 0x03;
	}
	return hex.EncodeToString(ret)
}

