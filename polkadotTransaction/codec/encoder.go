package codec

import (
	"fmt"
	"strings"
)

func Encode(typeString string, value interface{}) (res string, err error) {
	var bytes OffsetBytes
	typeString = strings.ToLower(typeString)

	switch typeString {
	case "bool":
		bytes, err = BoolToBytes(value)
	case "compact<u32>":
		fallthrough
	case "u8":
		fallthrough
	case "u16":
		fallthrough
	case "u32":
		fallthrough
	case "u64":
		fallthrough
	case "u128":
		bytes, err = IntToBytes(value)
	case "string":
		bytes, err = StringToBytes(value)
	default:
		err = fmt.Errorf("unknown format %v", typeString)
	}

	if err != nil {
		return
	}

	if strings.HasPrefix(typeString, "compact") {
		bytes, err = bytes.ToCompact()
	}

	if err == nil {
		res = bytes.ToHex()
	}
	return
}
