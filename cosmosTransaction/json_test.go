package cosmosTransaction

import (
	"encoding/json"
	"fmt"
	"testing"
)

func Test_json(t *testing.T) {
	tx := TxStruct{
		AccountNumber: "1858",
		ChainID:       "gaia-13003",
		Fee: FeeStruct{
			Amount: Coins{},
			Gas:    "200000",
		},
		Memo:     "",
		Message:  []Message{NewMessage("cosmos-sdk/MsgSend", NewMsgSend("cosmos1x9rdj3pgk9l3fvuj0fzxwa38vz276ljcysewnn", "cosmos1xv66sa5tlplm68j4fec6stdzszg3pcvswag06j", Coins{NewCoin("muon", 1000000)}))},
		Sequence: "2",
	}

	b, err := json.Marshal(tx)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(b))
}
