package bigbangTransaction

import "errors"

type TxIn struct {
	TxID []byte
	Vout byte
}

func NewTxIn(txid string, vout byte) (*TxIn, error) {
	if txid == "" || len(txid) != 64 {
		return nil, errors.New("Invalid txid!")
	}

	txidBytes, err := reverseHexToBytes(txid)
	if err != nil {
		return nil, err
	}

	return &TxIn{
		TxID: txidBytes,
		Vout: vout,
	}, nil
}

func (id TxIn) ToBytes() []byte {
	return append(id.TxID, id.Vout)
}
