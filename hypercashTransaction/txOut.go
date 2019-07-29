package hypercashTransaction

import "github.com/pkg/errors"

type TxOut struct {
	Amount          []byte
	PkScriptVersion []byte
	PKScript        []byte
}

func (out Vout) NewTxOut() (*TxOut, error) {
	var txOut TxOut

	txOut.Amount = uint64ToLittleEndianBytes(out.Amount)
	txOut.PkScriptVersion = uint16ToLittleEndianBytes(DefaultPkScriptVersion)

	pkPrefix, pkhaash, err := DecodeCheck(out.Address)
	if err != nil {
		return nil, err
	}
	if len(pkPrefix) != len(PKHAddressPrefix) || len(pkhaash) != 20 {
		return nil, errors.New("Invalid address!")
	}
	for i, h := range pkPrefix {
		if h != PKHAddressPrefix[i] {
			return nil, errors.New("Invalid address!")
		}
	}

	pkhaash = append([]byte{0x19, 0x76, 0xA9, 0x14}, pkhaash...)
	pkhaash = append(pkhaash, []byte{0x88, 0xAC}...)

	txOut.PKScript = pkhaash

	return &txOut, nil
}

func (out *TxOut) ToBytes() []byte {
	ret := make([]byte, 0)

	ret = append(ret, out.Amount...)
	ret = append(ret, out.PkScriptVersion...)
	ret = append(ret, out.PKScript...)

	return ret
}