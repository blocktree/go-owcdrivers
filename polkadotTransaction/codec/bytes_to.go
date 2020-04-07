package codec

import (
	"encoding/binary"
	"fmt"
)

// Primitive types

func (sb *OffsetBytes) ToUint16() (res uint16, err error) {
	bytes, err := sb.GetNextBytes(2)
	if err != nil {
		return
	}
	bytes = ExtendLEBytes(bytes, 2)
	res = binary.LittleEndian.Uint16(bytes)
	return
}

func (sb *OffsetBytes) ToBool() (res bool, err error) {
	b, err := sb.GetNextByte()
	if err != nil {
		return
	}
	switch b {
	case 0:
		res = false
	case 1:
		res = true
	default:
		err = fmt.Errorf("invalid value %v for data type `bool`", b)
	}
	return
}

func (sb *OffsetBytes) ToString() (res string, err error) {
	bytes, err := sb.FromCompact()
	if err != nil {
		return
	}
	res = string(bytes.GetAll())
	return
}

func (sb *OffsetBytes) ToEnumValue(enum []string) (res string, err error) {
	intValue, err := sb.GetNextByte()
	index := int(intValue)
	if index > len(enum)-1 {
		err = fmt.Errorf("index out of range")
		return
	}
	res = enum[index]
	return
}

// Complex types
func (sb *OffsetBytes) ToHexBytes() (res string, err error) {
	bytes, err := sb.FromCompact()
	if err != nil {
		return
	}
	res = bytes.ToHex()
	return
}

func (sb *OffsetBytes) ToH256() (res string, err error) {
	bb, err := sb.GetNextBytes(32)
	if err != nil {
		return
	}
	bytes, err := NewBytes(bb)
	if err != nil {
		return
	}
	res = bytes.ToHex()
	return
}

func (sb *OffsetBytes) ToCompactUint128() (res U128, err error) {
	bytes, err := sb.FromCompact()
	if err != nil {
		return
	}
	res, err = bytes.ToUint128()
	return
}

func (sb *OffsetBytes) ToCompactUInt32() (res U32, err error) {
	bytes, err := sb.FromCompact()
	if err != nil {
		return
	}
	res, err = bytes.ToUint32()
	return
}

func (sb *OffsetBytes) ToVecCount() (res U32, err error) {
	bytes, err := sb.FromCompact()
	if err != nil {
		return
	}
	res, err = bytes.ToUint32()
	return
}
