package hypercashTransaction


func createPayloadSimpleSend(propertyID uint32, amount uint64) []byte {
	messageType := uint16(0)
	messageVer := uint16(0)

	ret := []byte{}

	ret = append(ret, uint16ToBigEndianBytes(messageVer)...)
	ret = append(ret, uint16ToBigEndianBytes(messageType)...)
	ret = append(ret, uint32ToBigEndianBytes(propertyID)...)
	ret = append(ret, uint64ToBigEndianBytes(amount)...)

	ret = append([]byte("omni"), ret...)
	ret = append([]byte{byte(len(ret))}, ret...)
	ret = append([]byte{OP_RETURN}, ret...)
	ret = append([]byte{byte(len(ret))}, ret...)
	return ret
}