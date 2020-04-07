package codec

const (
	modeBits = 2

	singleMode   byte = 0
	twoByteMode  byte = 1
	fourByteMode byte = 2
	bigIntMode   byte = 3

	singleModeMaxValue   = 63
	twoByteModeMaxValue  = 16383
	fourByteModeMaxValue = 1073741823
)

var modeToNumOfBytes = map[byte]uint{
	singleMode:   1,
	twoByteMode:  2,
	fourByteMode: 4,
}

func GetNumOfBytesByUint32(i uint32) (res int) {
	mode := bigIntMode

	if i <= singleModeMaxValue {
		mode = singleMode
	} else if i <= twoByteModeMaxValue {
		mode = twoByteMode
	} else if i <= fourByteModeMaxValue {
		mode = fourByteMode
	}

	numOfBytes, _ := modeToNumOfBytes[mode]
	return int(numOfBytes)
}

func GetNumOfBytes(b byte) (res int) {
	var ures uint

	mode := b & bigIntMode
	if mode == bigIntMode {
		ures |= uint(b) >> modeBits
		ures += 4
	} else {
		ures = modeToNumOfBytes[mode]
	}

	res = int(ures)
	return
}

func CompactBytesToBytes(bytes []byte) []byte {
	for i := range bytes {
		if i != 0 {
			b := bytes[i] & bigIntMode
			b = b << 6
			bytes[i-1] |= b
		}
		bytes[i] = bytes[i] >> modeBits
	}
	return bytes
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
