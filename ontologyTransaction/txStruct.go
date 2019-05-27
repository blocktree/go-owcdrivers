package ontologyTransaction

import (
	"encoding/hex"
	"errors"
)

type Transaction struct {
	Version    byte
	TxType     byte
	Nonce      []byte
	GasPrice   []byte
	GaseLimit  []byte
	Payer      []byte
	Payload    []byte
	Attributes byte
	SigDatas   []SigData
}

func NewEmptyTransaction(assetType int, txType byte, nonce uint32, gasPrice, gasLimit uint64, payer string, payload []byte) Transaction {
	var version byte
	if assetType == AssetONT {
		version = ONTContractVersion
	} else {
		version = ONGContractVersion
	}
	_, payerBytes, _ := DecodeCheck(payer)
	return Transaction{version, txType, uint32ToLittleEndianBytes(nonce), uint64ToLittleEndianBytes(gasPrice), uint64ToLittleEndianBytes(gasLimit), payerBytes, payload, DefaultAttribute, nil}
}

func (t Transaction) GetVersion() byte {
	return t.Version
}

func (t Transaction) GetTxType() byte {
	return t.TxType
}

func (t Transaction) GetNonce() uint32 {
	return littleEndianBytesToUint32(t.Nonce)
}

func (t Transaction) GetGasPrice() uint64 {
	return littleEndianBytesToUint64(t.GasPrice)
}

func (t Transaction) GetGasLimit() uint64 {
	return littleEndianBytesToUint64(t.GaseLimit)
}

func (t Transaction) GetPayLoad() string {
	return hex.EncodeToString(t.Payload)
}

func (t Transaction) GetPayer() string {
	return EncodeCheck(AddressPrefix, t.Payer)
}

func (t Transaction) ToBytes() ([]byte, error) {

	ret := []byte{}

	ret = append(ret, t.Version)
	ret = append(ret, t.TxType)
	if t.Nonce == nil || len(t.Nonce) != 4 {
		return nil, errors.New("Invalid nonce!")
	}
	ret = append(ret, t.Nonce...)
	if t.GasPrice == nil || len(t.GasPrice) != 8 {
		return nil, errors.New("Invalid gasprice!")
	}
	ret = append(ret, t.GasPrice...)
	if t.GaseLimit == nil || len(t.GaseLimit) != 8 {
		return nil, errors.New("Invalid gaslimit!")
	}
	ret = append(ret, t.GaseLimit...)
	if t.Payer == nil || len(t.Payer) != 0x14 {
		return nil, errors.New("Invalid payer!")
	}
	ret = append(ret, t.Payer...)
	if t.Payload == nil || len(t.Payload) == 0 {
		return nil, errors.New("Invalid invoke code!")
	}
	ret = append(ret, byte(len(t.Payload)))
	ret = append(ret, t.Payload...)
	ret = append(ret, t.Attributes)

	if t.SigDatas == nil {
		ret = append(ret, 0x00)
	} else {
		if t.SigDatas[0].Nrequired == 0 {
			ret = append(ret, byte(len(t.SigDatas[0].SigPubs)))
			for _, sp := range t.SigDatas[0].SigPubs {
				ret = append(ret, sp.toBytes()...)
			}

		} else {
			// TODO
		}

	}
	return ret, nil
}

func DecodeRawTransaction(txBytes []byte) (*Transaction, error) {
	var tx Transaction
	if txBytes == nil || len(txBytes) == 0 {
		return nil, errors.New("Invalid transaction data!")
	}
	limit := len(txBytes)
	index := 0

	if index+1 > limit {
		return nil, errors.New("Invalid trnsaction data!")
	}

	if txBytes[index] != 0x00 {
		return nil, errors.New("Invalid trnsaction data!")
	}
	index++

	if index+1 > limit {
		return nil, errors.New("Invalid trnsaction data!")
	}

	if txBytes[index] != TxTypeInvoke {
		return nil, errors.New("Only invoke transaction type supported now!")
	}
	tx.TxType = txBytes[index]
	index++

	if index+4 > limit {
		return nil, errors.New("Invalid trnsaction data!")
	}

	tx.Nonce = txBytes[index : index+4]
	index += 4

	if index+8 > limit {
		return nil, errors.New("Invalid trnsaction data!")
	}

	tx.GasPrice = txBytes[index : index+8]
	index += 8

	if index+8 > limit {
		return nil, errors.New("Invalid trnsaction data!")
	}

	tx.GaseLimit = txBytes[index : index+8]
	index += 8

	if index+20 > limit {
		return nil, errors.New("Invalid trnsaction data!")
	}

	tx.Payer = txBytes[index : index+20]
	index += 20

	if index+1 > limit {
		return nil, errors.New("Invalid trnsaction data!")
	}

	payloadLen := txBytes[index]
	index++

	if payloadLen == 0 {
		return nil, errors.New("Invalid trnsaction data!")
	}

	if index+int(payloadLen) > limit {
		return nil, errors.New("Invalid trnsaction data!")
	}

	tx.Payload = txBytes[index : index+int(payloadLen)]

	index += int(payloadLen)

	if index+1 > limit {
		return nil, errors.New("Invalid trnsaction data!")
	}

	tx.Attributes = DefaultAttribute
	if txBytes[index] != DefaultAttribute {
		return nil, errors.New("Default attribute is zero right now!")
	}
	index++

	if index+1 > limit {
		return nil, errors.New("Invalid trnsaction data!")
	}

	if txBytes[index] == 0x00 {
		tx.SigDatas = nil
		index++
		if index != limit {
			return nil, errors.New("Invalid transaction data!")
		}
	} else if txBytes[index] == 0x01 {
		sigpub, err := decodeSigPubBytes(txBytes[index:])
		if err != nil {
			return nil, err
		}
		tx.SigDatas = append(tx.SigDatas, SigData{0, []SigPub{*sigpub}})
	} else {
		sigLen := int(txBytes[index])
		index++

		for i := 0; i < sigLen; i++ {
			if index+102 > limit {
				return nil, errors.New("Invalid transaction data!")
			}
			sigpub, err := decodeSigPubBytes(txBytes[index : index+102])
			if err != nil {
				return nil, err
			}
			tx.SigDatas = append(tx.SigDatas, SigData{0, []SigPub{*sigpub}})
			index += 102
		}
		if index != limit {
			return nil, errors.New("Invalid transaction data!")
		}
	}

	return &tx, nil
}

func (t Transaction) cloneEmpty() Transaction {
	var ret Transaction
	ret.Version = t.Version
	ret.TxType = t.TxType
	ret.Nonce = t.Nonce
	ret.GasPrice = t.GasPrice
	ret.GaseLimit = t.GaseLimit
	ret.Payer = t.Payer
	ret.Payload = t.Payload
	ret.Attributes = t.Attributes
	ret.SigDatas = nil

	return ret
}
