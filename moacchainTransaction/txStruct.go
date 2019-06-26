package moacchainTransaction

import (
	"errors"
	"math/big"
)

type TxStruct struct {
	Head           []byte
	Nonce          []byte
	SystemContract []byte
	GasPrice       []byte
	GasLimit       []byte
	Recipient      []byte
	Amount         []byte
	Payload        []byte
	ShardingFlag   []byte
	Via            []byte
	ChainID        []byte
	R              []byte
	S              []byte
}

func NewTxStruct(to string, nonce uint64, amount, gasLimit, gasPrice *big.Int, signature []byte, isTestNet bool) (*TxStruct, error) {
	var tx TxStruct
	tx.Nonce = getUint64Bytes(nonce)
	tx.SystemContract = getUint64Bytes(0) // not contract
	tx.GasPrice = getBigIntBytes(gasPrice)
	tx.GasLimit = getBigIntBytes(gasLimit)
	tx.Amount = getBigIntBytes(amount)
	hash, err := getAddressHashBytes(to)
	if err != nil {
		return nil, err
	}
	tx.Recipient = hash
	tx.Payload = getLengthBytes(0)      // no payload
	tx.ShardingFlag = getUint64Bytes(0) // global transaction
	tx.Via = getUint64Bytes(0)
	if isTestNet {
		tx.ChainID = []byte{ChainIDTestnet}
	} else {
		tx.ChainID = []byte{ChainIDMainnet}
	}

	if signature == nil {
		tx.R = getLengthBytes(0)
		tx.S = getLengthBytes(0)
	} else {
		tx.R = getLengthBytes(32)
		tx.R = append(tx.R, signature[:32]...)
		tx.S = getLengthBytes(32)
		tx.S = append(tx.S, signature[32:]...)
	}

	return &tx, nil
}

func (tx *TxStruct) ToBytes() []byte {
	body := []byte{}

	body = append(body, tx.Nonce...)
	body = append(body, tx.SystemContract...)
	body = append(body, tx.GasPrice...)
	body = append(body, tx.GasLimit...)
	body = append(body, tx.Recipient...)
	body = append(body, tx.Amount...)
	body = append(body, tx.Payload...)
	body = append(body, tx.ShardingFlag...)
	body = append(body, tx.Via...)
	body = append(body, tx.ChainID...)
	body = append(body, tx.R...)
	body = append(body, tx.S...)

	head := getHeadBytes(SmallTag, LargeTag, uint64(len(body)))

	return append(head, body...)
}

func decodeEmpty(txBytes []byte) (*TxStruct, error) {
	var tx TxStruct
	limit := len(txBytes)
	index := 0

	if index+1 > limit {
		return nil, errors.New("Invalid!")
	}
	if txBytes[index] <= 0x80 {
		tx.Nonce = txBytes[index : index+1]
		index++
	} else {
		if index+1+int(txBytes[index])-0x80 > limit {
			return nil, errors.New("Invalid!")
		}
		tx.Nonce = txBytes[index : index+1+int(txBytes[index])-0x80]
		index += (1 + int(txBytes[index]) - 0x80)
	}

	if index+1 > limit || txBytes[index] < 0x80 {
		return nil, errors.New("Invalid!")
	}
	if index+1+int(txBytes[index])-0x80 > limit {
		return nil, errors.New("Invalid!")
	}
	tx.SystemContract = txBytes[index : index+1+int(txBytes[index])-0x80]
	index += (1 + int(txBytes[index]) - 0x80)

	if index+1 > limit || txBytes[index] < 0x80 {
		return nil, errors.New("Invalid!")
	}
	if index+1+int(txBytes[index])-0x80 > limit {
		return nil, errors.New("Invalid!")
	}
	tx.GasPrice = txBytes[index : index+1+int(txBytes[index])-0x80]
	index += (1 + int(txBytes[index]) - 0x80)

	if index+1 > limit || txBytes[index] < 0x80 {
		return nil, errors.New("Invalid!")
	}
	if index+1+int(txBytes[index])-0x80 > limit {
		return nil, errors.New("Invalid!")
	}
	tx.GasLimit = txBytes[index : index+1+int(txBytes[index])-0x80]
	index += (1 + int(txBytes[index]) - 0x80)

	if index+1 > limit || txBytes[index] < 0x80 {
		return nil, errors.New("Invalid!")
	}
	if index+1+int(txBytes[index])-0x80 > limit {
		return nil, errors.New("Invalid!")
	}
	tx.Recipient = txBytes[index : index+1+int(txBytes[index])-0x80]
	index += (1 + int(txBytes[index]) - 0x80)

	if index+1 > limit || txBytes[index] < 0x80 {
		return nil, errors.New("Invalid!")
	}
	if index+1+int(txBytes[index])-0x80 > limit {
		return nil, errors.New("Invalid!")
	}
	tx.Amount = txBytes[index : index+1+int(txBytes[index])-0x80]
	index += (1 + int(txBytes[index]) - 0x80)

	if index+1 > limit || txBytes[index] < 0x80 {
		return nil, errors.New("Invalid!")
	}
	if index+1+int(txBytes[index])-0x80 > limit {
		return nil, errors.New("Invalid!")
	}
	tx.Payload = txBytes[index : index+1+int(txBytes[index])-0x80]
	index += (1 + int(txBytes[index]) - 0x80)

	if index+1 > limit || txBytes[index] < 0x80 {
		return nil, errors.New("Invalid!")
	}
	if index+1+int(txBytes[index])-0x80 > limit {
		return nil, errors.New("Invalid!")
	}
	tx.ShardingFlag = txBytes[index : index+1+int(txBytes[index])-0x80]
	index += (1 + int(txBytes[index]) - 0x80)

	if index+1 > limit || txBytes[index] < 0x80 {
		return nil, errors.New("Invalid!")
	}
	if index+1+int(txBytes[index])-0x80 > limit {
		return nil, errors.New("Invalid!")
	}
	tx.Via = txBytes[index : index+1+int(txBytes[index])-0x80]
	index += (1 + int(txBytes[index]) - 0x80)

	if index+1 > limit {
		return nil, errors.New("Invalid!")
	}

	tx.ChainID = txBytes[index : index+1]
	index += 1

	if index+2 != limit || txBytes[index] != 0x80 || txBytes[index+1] != 0x80 {
		return nil, errors.New("Invalid!")
	}

	return &tx, nil
}

func (tx *TxStruct) addSig(sig []byte, isTestNet bool) {
	r := sig[:32]
	for _, data := range r {
		if data == 0x00 {
			r = r[1:]
		} else {
			break
		}
	}
	tx.R = getLengthBytes(len(r))
	tx.R = append(tx.R, r...)

	s := sig[32:64]
	for _, data := range s {
		if data == 0x00 {
			s = s[1:]
		} else {
			break
		}
	}
	tx.S = getLengthBytes(len(s))
	tx.S = append(tx.S, s...)

	if isTestNet {
		tx.ChainID = getUint64Bytes(uint64(sig[64] + 35 + ChainIDTestnet*2))
	} else {
		tx.ChainID = getUint64Bytes(uint64(sig[64] + 35 + ChainIDMainnet*2))
	}

}
