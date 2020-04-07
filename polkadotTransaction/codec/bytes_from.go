package codec

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
)

func (sb *OffsetBytes) FromCompact() (res OffsetBytes, err error) {
	b, err := sb.GetNextByte()
	if err != nil {
		return
	}
	numOfBytes := GetNumOfBytes(b)
	if numOfBytes <= 4 {
		sb.Reset()
	}
	bytes, err := sb.GetNextBytes(numOfBytes)
	if err != nil {
		return
	}
	if numOfBytes <= 4 {
		bytes = CompactBytesToBytes(bytes)
	}
	res, err = NewBytes(bytes)
	return
}

func BoolToBytes(value interface{}) (res OffsetBytes, err error) {
	b, ok := value.(bool)
	if !ok {
		err = fmt.Errorf("wrong type of value")
		return
	}
	if b {
		res, err = NewBytes([]byte{1})
	} else {
		res, err = NewBytes([]byte{0})
	}
	return
}

func intToLEBytes(value interface{}) (res []byte, err error) {
	buff := new(bytes.Buffer)
	err = binary.Write(buff, binary.LittleEndian, value)
	if err != nil {
		return
	}
	res = buff.Bytes()
	return
}

func IntToBytes(value interface{}) (res OffsetBytes, err error) {
	var bytes []byte

	switch t := value.(type) {
	case uint8:
		i, _ := value.(uint8)
		bytes, err = intToLEBytes(i)
	case uint16:
		i, _ := value.(uint16)
		bytes, err = intToLEBytes(i)
	case uint32:
		i, _ := value.(uint32)
		bytes, err = intToLEBytes(i)
	case uint64:
		i, _ := value.(uint64)
		bytes, err = intToLEBytes(i)
	case big.Int:
		i, _ := value.(big.Int)
		bytes = RevertBytes(i.Bytes())
	default:
		err = fmt.Errorf("wrong type of value %T", t)
		return

	}
	if err != nil {
		return
	}
	bytes = RemoveExtraLEBytes(bytes)
	res, err = NewBytes(bytes)
	return
}

func StringToBytes(value interface{}) (res OffsetBytes, err error) {
	switch t := value.(type) {
	case string:
		s, _ := value.(string)
		res, err = NewBytes([]byte(s))
	default:
		err = fmt.Errorf("wrong type of value %T", t)
		return
	}
	return
}
