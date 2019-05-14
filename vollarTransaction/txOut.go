package vollarTransaction

import (
	"encoding/hex"
	"errors"
)

const (
	p2pkhPrefix    = "101c"
	p2shPrefix     = "1041"
	DefaultOutFlag = byte(0)
)

var FixedHashData = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

type TxOut struct {
	Amount     []byte
	Flag       byte
	LockScript []byte
	HashData   []byte
}

func (out Vout) NewTxOut() (*TxOut, error) {
	prefix, lockScript, err := DecodeCheck(out.Address)

	if err != nil {
		return nil, errors.New("Invalid address to send!")
	}

	if hex.EncodeToString(prefix) == p2pkhPrefix {
		lockScript = append([]byte{0x19, 0x76, 0xa9, 0x14}, lockScript...)
		lockScript = append(lockScript, []byte{0x88, 0xAC}...)
	} else if hex.EncodeToString(prefix) == p2shPrefix {
		lockScript = append([]byte{0x17, 0xa9, 0x14}, lockScript...)
		lockScript = append(lockScript, byte(0x87))
	} else {
		return nil, errors.New("Unsupport address to send!")
	}

	return &TxOut{
		Amount:     uint64ToLittleEndianBytes(out.Amount),
		Flag:       DefaultOutFlag,
		LockScript: lockScript,
		HashData:   FixedHashData,
	}, nil
}

func (out TxOut) ToBytes() []byte {
	ret := []byte{}
	ret = append(ret, out.Amount...)
	ret = append(ret, out.Flag)
	ret = append(ret, out.LockScript...)
	ret = append(ret, out.HashData...)
	return ret
}
