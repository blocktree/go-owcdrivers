package moacchainTransaction

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
)

func Test_transaction(t *testing.T) {
	to := "0xeb916695b6d6a8f9c18f344754f13b7b11d62268"
	nonce := uint64(1)
	gasPrice := big.NewInt(6000)
	gasLimit := big.NewInt(200)
	amount := big.NewInt(40000)

	emptyTrans, hash, err := CreateEmptyRawTransactionAndHash(to, nonce, amount, gasLimit, gasPrice, false)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Println("空交易单 : \n", emptyTrans)
		fmt.Println("哈希    : \n", hash)
	}

	privkey, _ := hex.DecodeString("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
	sig, err := SignRawTransaction(hash, privkey)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Println("sig : \n", hex.EncodeToString(sig))
	}

	pubkey := "034EE1C207899C24D00B1B918C42F798C8BE8A46AD22DE0B57F6774C026C7D11AB"

	pass, signedTrans := VerifyAndCombineRawTransaction(emptyTrans, hex.EncodeToString(sig), pubkey, false)
	if pass {
		fmt.Println("合并之后的交易单 : \n", signedTrans)
	} else {
		t.Error("Verify falid !")
	}
}
