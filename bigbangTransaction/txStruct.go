package bigbangTransaction

import (
	"errors"
	"github.com/blocktree/go-owcrypt"
)

type TxStruct struct{
	Version   []byte
	Type      []byte
	Time      []byte
	LockUntil []byte
	Anchor    []byte
	Vins      []*TxIn
	To        []byte
	Amount    []byte
	Fee       []byte
	Data      []byte
}

func NewTxStruct(version, txtype uint16, timestamp, lockUntil uint32, anchor string, inputs []Vin, to string, amount, fee uint64, data string) (*TxStruct, error) {
	var tx TxStruct

	tx.Version = uint16ToLittleEndianBytes(version)
	tx.Type = uint16ToLittleEndianBytes(txtype)

	tx.Time = uint32ToLittleEndianBytes(timestamp)
	tx.LockUntil = uint32ToLittleEndianBytes(lockUntil)

	anchorBytes, err := reverseHexToBytes(anchor)
	if err != nil {
		return nil, errors.New("Invalid anchor string!")
	}
	tx.Anchor = anchorBytes

	if inputs == nil || len(inputs) == 0 {
		return nil, errors.New("Miss input!")
	}

	for _, in := range inputs {
		input, err := NewTxIn(in.TxID, in.Vout)
		if err != nil {
			return nil, err
		}
		tx.Vins = append(tx.Vins, input)
	}

	toBytes, err := addressDecode(to)
	if err != nil {
		return nil, err
	}

	tx.To = toBytes
	if amount == 0 {
		return nil, errors.New("Invalid amount!")
	}
	tx.Amount = uint64ToLittleEndianBytes(amount)
	if fee == 0 {
		return nil, errors.New("Invalid fee!")
	}
	tx.Fee = uint64ToLittleEndianBytes(fee)
	if data == "" {
		tx.Data = []byte{0x00}
	} else {
		tx.Data = append([]byte{byte(len(data))}, []byte(data)...)
	}

	return &tx, nil
}

func (tx TxStruct) ToBytes() []byte {
	ret := make([]byte, 0)

	ret = append(ret, tx.Version...)
	ret = append(ret, tx.Type...)
	ret = append(ret, tx.Time...)
	ret = append(ret, tx.LockUntil...)
	ret = append(ret, tx.Anchor...)
	ret = append(ret, byte(len(tx.Vins)))
	for _, in := range tx.Vins {
		ret = append(ret, in.ToBytes()...)
	}
	ret = append(ret, tx.To...)
	ret = append(ret, tx.Amount...)
	ret = append(ret, tx.Fee...)
	ret = append(ret, tx.Data...)

	return ret
}

func (tx TxStruct) GetHash() []byte {
	return owcrypt.Hash(tx.ToBytes(), 32, owcrypt.HASH_ALG_BLAKE2B)
}