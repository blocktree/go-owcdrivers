package bitcoincashTransaction

import (
	"errors"
)

type TxOut struct {
	amount     []byte
	lockScript []byte
}

func newTxOutForEmptyTrans(vout []Vout, addressPrefix AddressPrefix) ([]TxOut, error) {
	if vout == nil || len(vout) == 0 {
		return nil, errors.New("No address to send when create an empty transaction!")
	}
	var ret []TxOut
	var p2pkhPrefixByte []byte
	var p2wpkhPrefixByte []byte
	var p2shPrefixBytes []byte
	p2pkhPrefixByte = addressPrefix.P2PKHPrefix
	p2wpkhPrefixByte = addressPrefix.P2WPKHPrefix
	p2shPrefixBytes = addressPrefix.P2SHPrefix

	for _, v := range vout {
		amount := uint64ToLittleEndianBytes(v.Amount)

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
		} else if byteArrayCompare(prefix, p2wpkhPrefixByte) || byteArrayCompare(prefix, p2shPrefixBytes) {
			hash = append(hash, OpCodeEqual)
		} else {
			return nil, errors.New("Invalid address to send!")
		}

		ret = append(ret, TxOut{amount, hash})
	}
	return ret, nil
}

func newOmniTxOutForEmptyTrans(vout []Vout, omniDetail OmniStruct, addressPrefix AddressPrefix) ([]TxOut, error) {
	if vout == nil || len(vout) == 0 {
		return nil, errors.New("No address to send when create an empty transaction!")
	}
	var ret []TxOut
	var p2pkhPrefixByte []byte
	var p2wpkhPrefixByte []byte
	p2pkhPrefixByte = addressPrefix.P2PKHPrefix
	p2wpkhPrefixByte = addressPrefix.P2WPKHPrefix

	for _, v := range vout {
		amount := uint64ToLittleEndianBytes(v.Amount)

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
		} else if byteArrayCompare(prefix, p2wpkhPrefixByte) {
			hash = append(hash, OpCodeEqual)
		} else {
			return nil, errors.New("Invalid address to send!")
		}

		ret = append(ret, TxOut{amount, hash})
	}

	ret = append(ret, TxOut{uint64ToLittleEndianBytes(0), omniDetail.getPayload()})

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
