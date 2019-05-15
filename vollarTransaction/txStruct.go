package vollarTransaction

import (
	"encoding/hex"
	"errors"
	"strings"

	owcrypt "github.com/blocktree/go-owcrypt"
)

const DefaultTxFlag = byte(0)

var DefaultTxVersion = []byte{0x01, 0x00, 0x00, 0x00}

type TxStruct struct {
	Version []byte // 01000000
	Flag    byte   // 00
	Vin     []TxIn
	Vout    []TxOut
}

func NewTxStruct(vins []Vin, vouts []Vout) (*TxStruct, error) {
	ret := TxStruct{Version: DefaultTxVersion, Flag: DefaultTxFlag}

	for _, in := range vins {
		txin, err := in.NewTxIn()
		if err != nil {
			return nil, err
		}
		ret.Vin = append(ret.Vin, *txin)
	}

	for _, out := range vouts {
		txout, err := out.NewTxOut()
		if err != nil {
			return nil, err
		}
		ret.Vout = append(ret.Vout, *txout)
	}
	return &ret, nil
}

func (ts TxStruct) ToBytes() []byte {
	ret := []byte{}

	ret = append(ret, ts.Version...)
	ret = append(ret, ts.Flag)

	ret = append(ret, byte(len(ts.Vin)))
	for _, in := range ts.Vin {
		ret = append(ret, in.ToBytes()...)
	}

	ret = append(ret, byte(len(ts.Vout)))
	for _, out := range ts.Vout {
		ret = append(ret, out.ToBytes()...)
	}

	return ret
}

func (ts TxStruct) getPreviousHash() []byte {
	data := []byte{}
	for _, in := range ts.Vin {
		data = append(data, in.TxID...)
		data = append(data, in.Vout...)
	}
	return owcrypt.Hash(data, 0, owcrypt.HASh_ALG_DOUBLE_SHA256)
}

func (ts TxStruct) getSequenceHash() []byte {
	data := []byte{}
	for _, in := range ts.Vin {
		data = append(data, in.Sequence...)
	}
	return owcrypt.Hash(data, 0, owcrypt.HASh_ALG_DOUBLE_SHA256)
}

func (ts TxStruct) getOutputHash() []byte {
	data := []byte{}
	for _, out := range ts.Vout {
		data = append(data, out.Amount...)
		data = append(data, out.Flag)
		data = append(data, out.LockScript...)
		data = append(data, out.HashData...)
	}
	return owcrypt.Hash(data, 0, owcrypt.HASh_ALG_DOUBLE_SHA256)
}

func (ts TxStruct) GetHash() ([]string, error) {
	ret := []string{}
	if len(ts.Vin) == 0 {
		return nil, errors.New("inputs and lock scripts dismatch!")
	}
	previousHash := ts.getPreviousHash()
	sequenceHash := ts.getSequenceHash()
	outputHash := ts.getOutputHash()

	hashShieldedSpends := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	hashShieldedOutputs := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	lockTime := []byte{0x00, 0x00, 0x00, 0x00}
	expiryHeight := []byte{0x00, 0x00, 0x00, 0x00}
	valueBalance := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	sigType := []byte{0x01, 0x00, 0x00, 0x00} //all

	for _, in := range ts.Vin {
		data := []byte{}
		data = append(data, previousHash...)
		data = append(data, sequenceHash...)
		data = append(data, outputHash...)
		data = append(data, hashShieldedSpends...)
		data = append(data, hashShieldedOutputs...)
		data = append(data, lockTime...)
		data = append(data, expiryHeight...)
		data = append(data, valueBalance...)
		data = append(data, sigType...)
		data = append(data, in.TxID...)
		data = append(data, in.Vout...)

		data = append(data, in.LockScript...)
		data = append(data, in.Sequence...)

		hash := owcrypt.Hash(data, 0, owcrypt.HASh_ALG_DOUBLE_SHA256)
		ret = append(ret, hex.EncodeToString(hash))
	}
	return ret, nil
}

func DecodeTxStructRaw(trans string) (*TxStruct, []string, error) {
	txStruct := TxStruct{}
	dataArray := strings.Split(trans, ":")
	if len(dataArray) <= 1 {
		return nil, nil, errors.New("invalid transaction data!")
	}
	txBytes, err := hex.DecodeString(dataArray[0])
	if err != nil {
		return nil, nil, errors.New("invalid transactions!")
	}
	limit := len(txBytes)

	index := 0

	if index+4 > limit {
		return nil, nil, errors.New("invalid transaction data!")
	}
	txStruct.Version = txBytes[index : index+4]
	index += 4

	if index+1 > limit {
		return nil, nil, errors.New("invalid transaction data!")
	}
	txStruct.Flag = txBytes[index]
	index++

	if index+1 > limit {
		return nil, nil, errors.New("invalid transaction data!")
	}
	numVins := txBytes[index]
	index++

	for i := 0; i < int(numVins); i++ {
		in := TxIn{}
		if index+32 > limit {
			return nil, nil, errors.New("invalid transaction data!")
		}
		in.TxID = txBytes[index : index+32]
		index += 32
		if index+4 > limit {
			return nil, nil, errors.New("invalid transaction data!")
		}
		in.Vout = txBytes[index : index+4]
		index += 4
		if index+1 > limit {
			return nil, nil, errors.New("invalid transaction data!")
		}
		if txBytes[index] != 0 {
			return nil, nil, errors.New("input signed transaction ,while only  empty transaction can be decoded!")
		}
		index++
		if index+4 > limit {
			return nil, nil, errors.New("invalid transaction data!")
		}
		in.Sequence = txBytes[index : index+4]
		index += 4

		txStruct.Vin = append(txStruct.Vin, in)
	}

	if index+1 > limit {
		return nil, nil, errors.New("invalid transaction data!")
	}
	numVouts := txBytes[index]
	index++

	for i := 0; i < int(numVouts); i++ {
		out := TxOut{}
		if index+8 > limit {
			return nil, nil, errors.New("invalid transaction data!")
		}
		out.Amount = txBytes[index : index+8]
		index += 8
		if index+1 > limit {
			return nil, nil, errors.New("invalid transaction data!")
		}
		out.Flag = txBytes[index]
		index++
		if index+1 > limit {
			return nil, nil, errors.New("invalid transaction data!")
		}
		lockScriptLen := int(txBytes[index])
		if index+1+lockScriptLen > limit {
			return nil, nil, errors.New("invalid transaction data!")
		}
		out.LockScript = txBytes[index : index+1+lockScriptLen]
		index += (lockScriptLen + 1)
		if index+32 > limit {
			return nil, nil, errors.New("invalid transaction data!")
		}
		out.HashData = txBytes[index : index+32]
		index += 32

		txStruct.Vout = append(txStruct.Vout, out)
	}

	if index != limit {
		return nil, nil, errors.New("invalid transaction data!")
	}

	if len(txStruct.Vin) != len(dataArray)-1 {
		return nil, nil, errors.New("invalid transaction data!")
	}

	return &txStruct, dataArray[1:], nil
}
