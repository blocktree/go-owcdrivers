package fiiiTransaction

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
)

type OutputMsg struct {
	Index      int    `json:"Index"`
	Amount     int64  `json:"Amount"`
	Size       int    `json:"Size"`
	LockScript string `json:"LockScript"`
}

func (out Vout) NewOutputMsg(index int) (*OutputMsg, error) {
	ret := OutputMsg{}

	hash, err := DecodeCheck(out.Address, out.AddressPrefix)
	if err != nil {
		return nil, err
	}

	if out.Amount <= 0 {
		return nil, errors.New("Invalid amount to send!")
	}

	ret.Index = index
	ret.Amount = out.Amount
	ret.LockScript = genLockScript(hash)
	ret.Size = len(ret.LockScript)

	return &ret, nil
}

func genLockScript(hash []byte) string {
	return "OP_DUP OP_HASH160 " + strings.ToUpper(hex.EncodeToString(hash)) + " OP_EQUALVERIFY OP_CHECKSIG"
}

func (out OutputMsg) ToBytes() []byte {
	data := []byte{}

	index := make([]byte, 4)
	amount := make([]byte, 8)
	size := make([]byte, 4)

	binary.BigEndian.PutUint32(index, uint32(out.Index))
	binary.BigEndian.PutUint64(amount, uint64(out.Amount))
	binary.BigEndian.PutUint32(size, uint32(out.Size))

	data = append(data, index...)
	data = append(data, amount...)
	data = append(data, size...)
	data = append(data, []byte(out.LockScript)...)

	return data
}
