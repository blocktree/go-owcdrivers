package omniTransaction

import (
	"errors"
)

const (
	TypeEmpty    = 0
	TypeP2PKH    = 1
	TypeP2WPKH   = 2
	TypeBech32   = 3
	TypeMultiSig = 4
)

type TxIn struct {
	inType      int
	TxID        []byte
	Vout        []byte
	scriptPub   []byte
	scriptSig   []byte
	sequence    []byte
	scriptMulti []byte
}

func (in TxIn) GetUTXOType() int {
	return in.inType
}

func (in TxIn) GetTxID() string {
	return reverseBytesToHex(in.TxID)
}

func (in TxIn) GetVout() uint32 {
	return littleEndianBytesToUint32(in.Vout)
}

func newTxInForEmptyTrans(vin []Vin) ([]TxIn, error) {
	if vin == nil || len(vin) == 0 {
		return nil, errors.New("No input found when create an empty transaction!")
	}
	var ret []TxIn

	for _, v := range vin {
		txid, err := reverseHexToBytes(v.TxID)
		if err != nil || len(txid) != 32 {
			return nil, errors.New("Invalid previous transaction id!")
		}

		vout := uint32ToLittleEndianBytes(v.Vout)

		ret = append(ret, TxIn{TypeEmpty, txid, vout, nil, nil, nil, nil})
	}
	return ret, nil
}

func (vin *TxIn) setSequence(lockTime uint32, replaceable bool) {
	if replaceable {
		vin.sequence = uint32ToLittleEndianBytes(SequenceMaxBip125RBF)
	} else if lockTime != 0 {
		vin.sequence = uint32ToLittleEndianBytes(SequenceFinal - 1)
	} else {
		vin.sequence = uint32ToLittleEndianBytes(SequenceFinal)
	}
}

func (in TxIn) toBytes(SegwitON bool) ([]byte, error) {
	var ret []byte

	if in.TxID == nil || len(in.TxID) != 32 {
		return nil, errors.New("Invalid previous transaction id!")
	}
	if in.Vout == nil || len(in.Vout) != 4 {
		return nil, errors.New("Invalid previous transaction vout!")
	}

	ret = append(ret, in.TxID...)
	ret = append(ret, in.Vout...)
	if in.inType == TypeEmpty {
		if in.scriptPub == nil && in.scriptSig == nil {
			ret = append(ret, byte(0x00))
		} else {
			ret = append(ret, byte(len(in.scriptPub)))
			ret = append(ret, in.scriptPub...)
		}
	} else if in.inType == TypeP2PKH {
		ret = append(ret, byte(len(in.scriptSig)))
		ret = append(ret, in.scriptSig...)
	} else if in.inType == TypeP2WPKH {
		ret = append(ret, 0x17, 0x16)
		ret = append(ret, in.scriptPub...)
	} else if in.inType == TypeBech32 {
		ret = append(ret, 0x00)
	} else if in.inType == TypeMultiSig {
		if SegwitON {
			ret = append(ret, in.scriptPub...)
		} else {
			ret = append(ret, in.scriptMulti...)
		}
	} else {
		return nil, errors.New("Unknown type of transaction!")
	}

	if in.sequence == nil || len(in.sequence) != 4 {
		return nil, errors.New("Invalid previous transaction sequence!")
	}
	ret = append(ret, in.sequence...)
	return ret, nil
}

func (in TxIn) toSegwitBytes() ([]byte, error) {
	var ret []byte
	if in.inType == TypeP2PKH {
		ret = append(ret, 0x00)
	} else if in.inType == TypeP2WPKH || in.inType == TypeBech32 {
		ret = append(ret, 0x02)
		ret = append(ret, in.scriptSig...)
	} else if in.inType == TypeMultiSig {
		ret = append(ret, 0x04)
		ret = append(ret, in.scriptMulti...)
	} else {
		return nil, errors.New("Unknown type of transaction!")
	}
	return ret, nil
}

func (in *TxIn) setEmpty() {
	in.inType = TypeEmpty
	in.scriptPub = nil
	in.scriptSig = nil
}
