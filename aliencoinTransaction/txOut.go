package aliencoinTransaction

import (
	"errors"
)

const (
	p2pkhPrefix = byte(0x17)
	p2shPrefix  = byte(0x30)
)

type TxOut struct {
	Amount     []byte
	LockScript []byte
}

func (out Vout) NewTxOut() (*TxOut, error) {

	prefix, lockScript, err := DecodeCheck(out.Address)

	if err != nil {
		return nil, errors.New("Invalid address to send!")
	}

	if prefix == p2pkhPrefix {
		lockScript = append([]byte{0x19, 0x76, 0xa9, 0x14}, lockScript...)
		lockScript = append(lockScript, []byte{0x88, 0xAC}...)
	} else if prefix == p2shPrefix {
		lockScript = append([]byte{0x17, 0xa9, 0x14}, lockScript...)
		lockScript = append(lockScript, byte(0x87))
	} else {
		return nil, errors.New("Unsupport address to send!")
	}

	return &TxOut{
		Amount:     uint64ToLittleEndianBytes(out.Amount),
		LockScript: lockScript,
	}, nil
}

func (out TxOut) ToBytes() []byte {
	ret := []byte{}
	ret = append(ret, out.Amount...)
	ret = append(ret, out.LockScript...)
	return ret
}
