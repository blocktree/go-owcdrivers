package btcTransaction

import (
	"errors"
	"strings"
)

type TxOut struct {
	amount     []byte
	lockScript []byte
}

func newTxOutForEmptyTrans(vout []Vout) ([]TxOut, error) {
	if vout == nil || len(vout) == 0 {
		return nil, errors.New("No address to send when create an empty transaction!")
	}
	var ret []TxOut

	for _, v := range vout {
		amount := uint64ToLittleEndianBytes(v.Amount)

		if strings.Index(v.Address, Bech32Prefix) == 0 || strings.Index(v.Address, LTCBech32Prefix) == 0 {
			redeem, err := Bech32Decode(v.Address)
			if err != nil {
				return nil, errors.New("Invalid bech32 type address!")
			}

			redeem = append([]byte{byte(len(redeem))}, redeem...)
			redeem = append([]byte{0x00}, redeem...)

			ret = append(ret, TxOut{amount, redeem})
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
		if prefix == P2PKHPrefix || prefix == LTCP2PKHPrefix {
			hash = append(hash, OpCodeEqualVerify, OpCodeCheckSig)
			hash = append([]byte{OpCodeDup}, hash...)
		} else if prefix == P2WPKHPrefix || prefix == LTCP2WPKHPrefix {
			hash = append(hash, OpCodeEqual)
		} else {
			return nil, errors.New("Invalid address to send!")
		}

		ret = append(ret, TxOut{amount, hash})
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
