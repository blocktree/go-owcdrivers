package cxcTransaction

import (
	"errors"
	"strings"
)

func getTransferPayload(to AssetTransfer) []byte {
	ret := []byte(AssetTransferSign)

	sellfirstBytes, err := reverseHexToBytes(to.FirstSellTxID)
	if err != nil {
		return nil
	}

	ret = append(ret, sellfirstBytes...)
	ret = append(ret, uint64ToLittleEndianBytes(to.Amount)...)

	return ret
}

func getTransferAssetWithPayload(tos []AssetTransfer, addressPrefix AddressPrefix) (*[]TxOut, error) {

	var prefixStr string
	var p2pkhPrefixByte []byte
	var p2wpkhPrefixByte []byte
	prefixStr = addressPrefix.Bech32Prefix
	p2pkhPrefixByte = addressPrefix.P2PKHPrefix
	p2wpkhPrefixByte = addressPrefix.P2WPKHPrefix

	ret := make([]TxOut, 0)
	for _, to := range tos {
		if strings.Index(to.Address, prefixStr) == 0 {
			redeem, err := Bech32Decode(to.Address)
			if err != nil {
				return nil, errors.New("Invalid bech32 type address!")
			}

			redeem = append([]byte{byte(len(redeem))}, redeem...)
			redeem = append([]byte{0x00}, redeem...)
			payload := getTransferPayload(to)
			if payload == nil {
				return nil, errors.New("Failed to get asset payload!")
			}
			redeem = append(redeem, byte(len(payload)))
			redeem = append(redeem, payload...)
			redeem = append(redeem, OpDrop)
			ret = append(ret, TxOut{uint64ToLittleEndianBytes(0), redeem})
		}

		prefix, hash, err := DecodeCheck(to.Address)
		if err != nil {
			return nil, errors.New("Invalid address to send!")
		}

		if len(hash) != 0x14 {
			return nil, errors.New("Invalid address to send!")
		}

		hash = append([]byte{byte(len(hash))}, hash...)
		hash = append([]byte{OpCodeHash160}, hash...)
		if byteArrayCompare(prefix, p2pkhPrefixByte) {
			hash = append(hash, OpCodeEqualVerify, OpCodeCheckSig)
			hash = append([]byte{OpCodeDup}, hash...)
		} else if byteArrayCompare(prefix, p2wpkhPrefixByte) {
			hash = append(hash, OpCodeEqual)
		} else {
			return nil, errors.New("Invalid address to send!")
		}

		payload := getTransferPayload(to)
		if payload == nil {
			return nil, errors.New("Failed to get asset payload!")
		}
		hash = append(hash, byte(len(payload)))
		hash = append(hash, payload...)
		hash = append(hash, OpDrop)
		ret = append(ret, TxOut{uint64ToLittleEndianBytes(0), hash})
	}

	return &ret, nil
}
