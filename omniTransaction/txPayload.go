package omniTransaction

func createPayloadSimpleSend(propertyID uint32, amount uint64) []byte {
	messageType := uint16(0)
	messageVer := uint16(0)

	ret := []byte{}

	ret = append(ret, uint16ToBigEndianBytes(messageVer)...)
	ret = append(ret, uint16ToBigEndianBytes(messageType)...)
	ret = append(ret, uint32ToBigEndianBytes(propertyID)...)
	ret = append(ret, uint64ToBigEndianBytes(amount)...)

	return ret
}

func createPayloadSendAll(ecosystem byte) []byte {
	messageType := uint16(4)
	messageVer := uint16(0)

	ret := []byte{}

	ret = append(ret, uint16ToBigEndianBytes(messageVer)...)
	ret = append(ret, uint16ToBigEndianBytes(messageType)...)
	ret = append(ret, ecosystem)

	return ret
}

func createPayloadDExAccept(propertyID uint32, amount uint64) []byte {
	messageType := uint16(22)
	messageVer := uint16(0)

	ret := []byte{}

	ret = append(ret, uint16ToBigEndianBytes(messageVer)...)
	ret = append(ret, uint16ToBigEndianBytes(messageType)...)
	ret = append(ret, uint32ToBigEndianBytes(propertyID)...)
	ret = append(ret, uint64ToBigEndianBytes(amount)...)

	return ret
}

func createPayloadCloseCrowdsale(propertyID uint32) []byte {
	messageType := uint16(53)
	messageVer := uint16(0)

	ret := []byte{}

	ret = append(ret, uint16ToBigEndianBytes(messageVer)...)
	ret = append(ret, uint16ToBigEndianBytes(messageType)...)
	ret = append(ret, uint32ToBigEndianBytes(propertyID)...)

	return ret
}

func createPayloadGrant(propertyID uint32, amount uint64, memo string) []byte {
	messageType := uint16(55)
	messageVer := uint16(0)

	ret := []byte{}

	ret = append(ret, uint16ToBigEndianBytes(messageVer)...)
	ret = append(ret, uint16ToBigEndianBytes(messageType)...)
	ret = append(ret, uint32ToBigEndianBytes(propertyID)...)
	ret = append(ret, uint64ToBigEndianBytes(amount)...)

	if len(memo) > 255 {
		memo = memo[:255]
	}
	ret = append(ret, []byte(memo)...)
	ret = append(ret, 0)

	return ret
}

func createPayloadRevoke(propertyID uint32, amount uint64, memo string) []byte {
	messageType := uint16(56)
	messageVer := uint16(0)

	ret := []byte{}

	ret = append(ret, uint16ToBigEndianBytes(messageVer)...)
	ret = append(ret, uint16ToBigEndianBytes(messageType)...)
	ret = append(ret, uint32ToBigEndianBytes(propertyID)...)
	ret = append(ret, uint64ToBigEndianBytes(amount)...)

	if len(memo) > 255 {
		memo = memo[:255]
	}
	ret = append(ret, []byte(memo)...)
	ret = append(ret, 0)

	return ret
}

func createPayloadChangeIssuer(propertyID uint32) []byte {
	messageType := uint16(70)
	messageVer := uint16(0)

	ret := []byte{}

	ret = append(ret, uint16ToBigEndianBytes(messageVer)...)
	ret = append(ret, uint16ToBigEndianBytes(messageType)...)
	ret = append(ret, uint32ToBigEndianBytes(propertyID)...)

	return ret
}

func createPayloadEnableFreezing(propertyID uint32) []byte {
	messageType := uint16(71)
	messageVer := uint16(0)

	ret := []byte{}

	ret = append(ret, uint16ToBigEndianBytes(messageVer)...)
	ret = append(ret, uint16ToBigEndianBytes(messageType)...)
	ret = append(ret, uint32ToBigEndianBytes(propertyID)...)

	return ret
}

func createPayloadDisableFreezing(propertyID uint32) []byte {
	messageType := uint16(72)
	messageVer := uint16(0)

	ret := []byte{}

	ret = append(ret, uint16ToBigEndianBytes(messageVer)...)
	ret = append(ret, uint16ToBigEndianBytes(messageType)...)
	ret = append(ret, uint32ToBigEndianBytes(propertyID)...)

	return ret
}

func createPayloadFreezeTokens(propertyID uint32, amount uint64, address string) []byte {
	messageType := uint16(185)
	messageVer := uint16(0)

	ret := []byte{}

	ret = append(ret, uint16ToBigEndianBytes(messageVer)...)
	ret = append(ret, uint16ToBigEndianBytes(messageType)...)
	ret = append(ret, uint32ToBigEndianBytes(propertyID)...)
	ret = append(ret, uint64ToBigEndianBytes(amount)...)

	pre, addressByte, err := DecodeCheck(address)
	if err != nil {
		return nil
	}
	ret = append(ret, pre)
	ret = append(ret, addressByte...)

	return ret
}

func createPayloadUnfreezeTokens(propertyID uint32, amount uint64, address string) []byte {
	messageType := uint16(186)
	messageVer := uint16(0)

	ret := []byte{}

	ret = append(ret, uint16ToBigEndianBytes(messageVer)...)
	ret = append(ret, uint16ToBigEndianBytes(messageType)...)
	ret = append(ret, uint32ToBigEndianBytes(propertyID)...)
	ret = append(ret, uint64ToBigEndianBytes(amount)...)

	pre, addressByte, err := DecodeCheck(address)
	if err != nil {
		return nil
	}
	ret = append(ret, pre)
	ret = append(ret, addressByte...)

	return ret
}

func createPayloadMetaDExCancelEcosystem(ecosystem byte) []byte {
	messageType := uint16(28)
	messageVer := uint16(0)

	ret := []byte{}

	ret = append(ret, uint16ToBigEndianBytes(messageVer)...)
	ret = append(ret, uint16ToBigEndianBytes(messageType)...)
	ret = append(ret, ecosystem)

	return ret
}
