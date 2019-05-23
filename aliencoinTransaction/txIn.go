package aliencoinTransaction

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
)

type TxIn struct {
	TxID       []byte
	Vout       []byte
	SigPub     *SigPub
	Sequence   []byte
	LockScript []byte
}

func (in Vin) NewTxIn() (*TxIn, error) {
	txidBytes, err := reverseHexToBytes(in.TxID)
	if err != nil {
		return nil, errors.New("Invalid txid!")
	}

	vout := make([]byte, 4)
	binary.LittleEndian.PutUint32(vout[:], in.Vout)
	lockScript, err := hex.DecodeString(in.LockScript)
	if err != nil {
		return nil, errors.New("invalid lock script!")
	}
	lockScript = append([]byte{byte(len(lockScript))}, lockScript...)
	return &TxIn{
		TxID:       txidBytes,
		Vout:       vout,
		SigPub:     nil,
		Sequence:   []byte{0xff, 0xff, 0xff, 0xff},
		LockScript: lockScript,
	}, nil
}

func (in TxIn) ToBytes() []byte {
	ret := []byte{}
	ret = append(ret, in.TxID...)
	ret = append(ret, in.Vout...)
	if in.SigPub == nil {
		ret = append(ret, byte(0))
	} else {
		ret = append(ret, in.SigPub.ToBytes()...)
	}
	ret = append(ret, in.Sequence...)
	return ret
}
