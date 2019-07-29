package hypercashTransaction

import (
	"encoding/hex"
	"github.com/pkg/errors"
)

type TxIn struct {
	TxID            []byte
	Vout            []byte
	TxTree          byte
	Sequence        []byte
	SignatureScript []byte
	LockScript      []byte
}

func (in Vin) NewTxIn() (*TxIn, error) {
	var txIn TxIn

	txid, err := reverseHexToBytes(in.TxID)
	if err != nil || len(txid) != 32 {
		return nil, errors.New("Invalid previous transaction ID!")
	}
	txIn.TxID = txid

	txIn.Vout = uint32ToLittleEndianBytes(in.Vout)

	txIn.TxTree = TxTreeRegular

	txIn.Sequence = []byte{0xff, 0xff, 0xff, 0xff}

	txIn.SignatureScript = uint64ToLittleEndianBytes(in.Amount)
	txIn.SignatureScript = append(txIn.SignatureScript, uint32ToLittleEndianBytes(in.BlockHeight)...)
	txIn.SignatureScript = append(txIn.SignatureScript, uint32ToLittleEndianBytes(in.BlockIndex)...)

	lockscript,err := hex.DecodeString(in.LockScript)
	if err != nil {
		return nil, errors.New("Invalid lock script!")
	}

	txIn.LockScript = append([]byte{byte(len(lockscript))}, lockscript...)

	return &txIn, nil
}

func (in *TxIn) ToBytes() []byte {
	ret := make([]byte, 0)

	ret = append(ret, in.TxID...)
	ret = append(ret, in.Vout...)
	ret = append(ret, in.TxTree)
	ret = append(ret, in.Sequence...)

	return ret
}