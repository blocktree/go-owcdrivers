package cosmosTransaction

import (
	"fmt"
	"testing"
)

func Test_case1(t *testing.T) {
	denom := "muon"
	chainID := "gaia-13003"
	accountNumber := 1858
	memo := ""
	sequence := 2
	from := "cosmos1x9rdj3pgk9l3fvuj0fzxwa38vz276ljcysewnn"
	to := "cosmos1xv66sa5tlplm68j4fec6stdzszg3pcvswag06j"
	amount := int64(1000000)

	gas := int64(200000)
	feeAmount := int64(0)

	fee := NewStdFee(gas, Coins{NewCoin(denom, feeAmount)})

	messageType := "cosmos-sdk/MsgSend"
	message := []Message{NewMessage(messageType, NewMsgSend(from, to, Coins{NewCoin(denom, amount)}))}

	tx := NewTxStruct(chainID, memo, accountNumber, sequence, &fee, message)

	emptyTrans, hash, err := tx.CreateEmptyTransactionAndHash()
	if err != nil {
		t.Error("create empty transaction failed!")
	} else {
		fmt.Println("empty transaction : ", emptyTrans)
		fmt.Println("hash : ", hash)
	}

	prikey := []byte{0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0}

	sig, err := SignTransactionHash(hash, prikey)

	if err != nil {
		t.Error("sign transaction failed!")
	} else {
		fmt.Println("signature: ", sig)
	}

	pubkey := []byte{0x03, 0x72, 0x47, 0x8b, 0xc9, 0x3a, 0xe8, 0x27, 0xa0, 0xd5, 0x8d, 0x5b, 0x1f, 0x31, 0xd1, 0x5d, 0x9d, 0x8c, 0xf2, 0x09, 0xcb, 0x1a, 0xe2, 0x04, 0x8b, 0xae, 0x54, 0x45, 0x73, 0x18, 0x19, 0xea, 0x14}
	keyType := "tendermint/PubKeySecp256k1"
	mode := "block"
	ret, err := tx.CreateJsonForSend(sig, pubkey, keyType, mode)
	if err != nil {
		t.Error("create json for send failed!")
	} else {
		fmt.Println("transaction for send: ", ret)
	}
}
