package evaioTransaction

import "strconv"

type FeeStruct struct {
	Amount Coins  `json:"amount"`
	Gas    string `json:"gas"`
}

func NewStdFee(gas int64, amount Coins) FeeStruct {

	if amount == nil {
		return FeeStruct{
			Amount: Coins{},
			Gas:    strconv.FormatInt(gas, 10),
		}
	}

	return FeeStruct{
		Amount: amount,
		Gas:    strconv.FormatInt(gas, 10),
	}
}
