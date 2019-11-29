package evaioTransaction

import "strconv"

type TxStruct struct {
	AccountNumber string    `json:"account_number"`
	ChainID       string    `json:"chain_id"`
	Fee           FeeStruct `json:"fee"`
	Memo          string    `json:"memo"`
	Message       []Message `json:"msgs"`
	Sequence      string    `json:"sequence"`
}

func NewTxStruct(chainID, memo string, accountNumber, sequence int, fee *FeeStruct, message []Message) TxStruct {
	if fee.Amount[0].Amount == "" {
		fee.Amount = Coins{}
	}
	return TxStruct{
		AccountNumber: strconv.FormatInt(int64(accountNumber), 10),
		ChainID:       chainID,
		Fee:           *fee,
		Memo:          memo,
		Message:       message,
		Sequence:      strconv.FormatInt(int64(sequence), 10),
	}
}
