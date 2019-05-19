package fiiiTransaction

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
)

type InputMsg struct {
	OutputTransactionHash string `json:"OutputTransactionHash"`
	OutputIndex           int    `json:"OutputIndex"`
	Size                  int    `json:"Size"`
	UnlockScript          string `json:"UnlockScript"`
	message               []byte
}

func (in Vin) NewInputMsg() (*InputMsg, error) {
	ret := InputMsg{}

	if len(in.TxID) != 64 {
		return nil, errors.New("Invalid UTXO!")
	}

	_, err := hex.DecodeString(in.TxID)
	if err != nil {
		return nil, err
	}

	ret.OutputTransactionHash = in.TxID
	ret.OutputIndex = in.Vout

	return &ret, nil
}

func (in Vin) genMessage() string {
	vout := make([]byte, 4)
	binary.BigEndian.PutUint32(vout[:], uint32(in.Vout))
	return in.TxID + hex.EncodeToString(vout)
}

func (in InputMsg) genMessageBytes() ([]byte, error) {
	msg, err := hex.DecodeString(in.OutputTransactionHash)
	if err != nil {
		return nil, errors.New("Invalid UTXO ID!")
	}
	vout := make([]byte, 4)
	binary.BigEndian.PutUint32(vout[:], uint32(in.OutputIndex))

	msg = append(msg, vout...)

	return msg, nil
}

func (in InputMsg) ToBytes() []byte {
	data, _ := hex.DecodeString(in.OutputTransactionHash)

	index := make([]byte, 4)
	size := make([]byte, 4)

	binary.BigEndian.PutUint32(index, uint32(in.OutputIndex))
	binary.BigEndian.PutUint32(size, uint32(in.Size))

	data = append(data, index...)
	data = append(data, size...)

	data = append(data, []byte(in.UnlockScript)...)

	return data
}
