package vergeTransaction

import (
	"encoding/hex"
	"errors"
	"strings"
	"time"

	owcrypt "github.com/blocktree/go-owcrypt"
)

var DefaultTxVersion = []byte{0x01, 0x00, 0x00, 0x00}
var DefaultSigTypeBytes = []byte{0x01, 0x00, 0x00, 0x00}

type TxStruct struct {
	Version      []byte // 01000000
	TimeInterval []byte
	Vin          []TxIn
	Vout         []TxOut
	LockTime     []byte
}

func NewTxStruct(vins []Vin, vouts []Vout, timeInterval, lockTime uint32) (*TxStruct, error) {
	ret := TxStruct{Version: DefaultTxVersion}

	timeuntil := uint32(time.Now().Unix())
	timeuntil += timeInterval

	ret.TimeInterval = uint32ToLittleEndianBytes(timeuntil)
	ret.LockTime = uint32ToLittleEndianBytes(lockTime)

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
	ret = append(ret, ts.TimeInterval...)
	ret = append(ret, byte(len(ts.Vin)))
	for _, in := range ts.Vin {
		ret = append(ret, in.ToBytes()...)
	}

	ret = append(ret, byte(len(ts.Vout)))
	for _, out := range ts.Vout {
		ret = append(ret, out.ToBytes()...)
	}

	ret = append(ret, ts.LockTime...)
	return ret
}

func (ts TxStruct) GetHash() ([]string, error) {
	hashes := []string{}
	for i := 0; i < len(ts.Vin); i++ {
		data := []byte{}
		data = append(data, ts.Version...)
		data = append(data, ts.TimeInterval...)
		data = append(data, byte(len(ts.Vin)))
		for index, in := range ts.Vin {
			data = append(data, in.TxID...)
			data = append(data, in.Vout...)
			if index == i {
				data = append(data, in.LockScript...)
			} else {
				data = append(data, byte(0))
			}
			data = append(data, in.Sequence...)
		}

		data = append(data, byte(len(ts.Vout)))
		for _, out := range ts.Vout {
			data = append(data, out.ToBytes()...)
		}

		data = append(data, ts.LockTime...)
		data = append(data, DefaultSigTypeBytes...)

		hashes = append(hashes, hex.EncodeToString(owcrypt.Hash(data, 0, owcrypt.HASh_ALG_DOUBLE_SHA256)))
	}

	return hashes, nil
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

	if index+4 > limit {
		return nil, nil, errors.New("invalid transaction data!")
	}
	txStruct.TimeInterval = txBytes[index : index+4]
	index += 4

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
		lockScriptLen := int(txBytes[index])
		if index+1+lockScriptLen > limit {
			return nil, nil, errors.New("invalid transaction data!")
		}
		out.LockScript = txBytes[index : index+1+lockScriptLen]
		index += (lockScriptLen + 1)

		txStruct.Vout = append(txStruct.Vout, out)
	}
	if index+4 > limit {
		return nil, nil, errors.New("invalid transaction data!")
	}
	txStruct.LockTime = txBytes[index : index+4]
	index += 4

	if index != limit {
		return nil, nil, errors.New("invalid transaction data!")
	}

	if len(txStruct.Vin) != len(dataArray)-1 {
		return nil, nil, errors.New("invalid transaction data!")
	}

	for i := 0; i < len(txStruct.Vin); i++ {
		lock, _ := hex.DecodeString(dataArray[i+1])
		lock = append([]byte{byte(len(lock))}, lock...)
		txStruct.Vin[i].LockScript = lock
	}

	return &txStruct, dataArray[1:], nil
}
