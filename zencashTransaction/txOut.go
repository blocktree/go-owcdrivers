package zencashTransaction

import (
	"encoding/binary"
	"errors"
	"strings"
)

type TxOut struct {
	amount      []byte
	lockScript  []byte
}

func newTxOutForEmptyTrans(vout []Vout, addressPrefix AddressPrefix, blockHash string, blockHeight uint64) ([]TxOut, error) {
	if vout == nil || len(vout) == 0 {
		return nil, errors.New("No address to send when create an empty transaction!")
	}
	var ret []TxOut
	var prefixStr string
	var p2pkhPrefixByte []byte
	var p2wpkhPrefixByte []byte
	prefixStr = addressPrefix.Bech32Prefix
	p2pkhPrefixByte = addressPrefix.P2PKHPrefix
	p2wpkhPrefixByte = addressPrefix.P2WPKHPrefix

	blockHashBytes, err := reverseHexToBytes(blockHash)
	if err != nil {
		return nil, errors.New("Invalid block hash!")
	}
	tmp := make([]byte, 8)
	binary.BigEndian.PutUint64(tmp, blockHeight)
	zerocount := 0
	for _, v := range tmp {
		if v == 0 {
			zerocount ++
		} else {
			break
		}
	}
	blockHeightBytes := reverseBytes(tmp[zerocount:])

	for _, v := range vout {
		amount := uint64ToLittleEndianBytes(v.Amount)

		if strings.Index(v.Address, prefixStr) == 0 {
			redeem, err := Bech32Decode(v.Address)
			if err != nil {
				return nil, errors.New("Invalid bech32 type address!")
			}

			redeem = append([]byte{byte(len(redeem))}, redeem...)
			redeem = append([]byte{0x00}, redeem...)

			ret = append(ret, TxOut{amount:amount, lockScript:redeem})
		}

		prefix, hash, err := DecodeCheck(v.Address)
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
			hash = append(hash, 0x20)
			hash = append(hash, blockHashBytes...)
			hash = append(hash, byte(len(blockHeightBytes)))
			hash = append(hash, blockHeightBytes...)
			hash = append(hash, OpCodeCheckBlockAtHeight)
		} else if byteArrayCompare(prefix, p2wpkhPrefixByte) {
			hash = append(hash, OpCodeEqual)
		} else {
			return nil, errors.New("Invalid address to send!")
		}


		ret = append(ret, TxOut{amount:amount, lockScript:hash})
	}
	return ret, nil
}

func (out TxOut) toBytes() ([]byte, error) {
	if out.amount == nil || len(out.amount) != 8 {
		return nil, errors.New("Invalid amount for a transaction output!")
	}
	if out.lockScript == nil || len(out.lockScript) == 0 {
		return nil, errors.New("Invalid lock script for a transaction output!")
	}

	ret := []byte{}
	ret = append(ret, out.amount...)
	ret = append(ret, byte(len(out.lockScript)))
	ret = append(ret, out.lockScript...)

	return ret, nil
}
