package polkadotTransaction

import "encoding/hex"

type TxPayLoad struct {
	Method []byte
	Era []byte
	Nonce []byte
	Fee []byte
	SpecVersion []byte
	GenesisHash []byte
	BlockHash []byte
	TxVersion []byte
}

func (t TxPayLoad) ToBytesString () string {
	payload := make([]byte, 0)

	payload = append(payload, t.Method...)
	payload = append(payload, t.Era...)
	payload = append(payload, t.Nonce...)
	payload = append(payload, t.Fee...)
	payload = append(payload, t.SpecVersion...)
	payload = append(payload, t.TxVersion...)
	payload = append(payload, t.GenesisHash...)
	payload = append(payload, t.BlockHash...)

	return hex.EncodeToString(payload)
}