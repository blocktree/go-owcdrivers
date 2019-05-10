package cosmosTransaction

import "encoding/base64"

type Pub struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func NewPub(pubkey []byte, curveType string) Pub {
	return Pub{
		Type:  curveType,
		Value: base64.StdEncoding.EncodeToString(pubkey),
	}
}

type Sig struct {
	Signature     string `json:"signature"`
	Pubkey        Pub    `json:"pub_key"`
	AccountNumber string `json:"account_number"`
	Sequence      string `json:"sequence"`
}

func NewSig(signature []byte, accountNumber, sequence string, pubkey Pub) Sig {
	return Sig{
		Signature:     base64.StdEncoding.EncodeToString(signature),
		Pubkey:        pubkey,
		AccountNumber: accountNumber,
		Sequence:      sequence,
	}
}

type Tx struct {
	Message   []Message `json:"msg"`
	Fee       FeeStruct `json:"fee"`
	Memo      string    `json:"memo"`
	Signature []Sig     `json:"signatures"`
}

func NewTx(message []Message, memo string, fee FeeStruct, signature []Sig) Tx {
	return Tx{
		Message:   message,
		Fee:       fee,
		Memo:      memo,
		Signature: signature,
	}
}

type TxSend struct {
	Tx   Tx     `json:"tx"`
	Mode string `json:"mode"`
}

func NewTxSend(tx Tx, mode string) TxSend {
	return TxSend{
		Tx:   tx,
		Mode: mode,
	}
}
