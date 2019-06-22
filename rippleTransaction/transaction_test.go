package rippleTransaction

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestTransaction(t *testing.T) {
	from := "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
	pubkey := "0330e7fc9d56bb25d6893ba3f317ae5bcf33b3291bd63db32654a313222f7fd020"
	to := "rb1fWuuAEtPUaeEWxocV3h4x5JwDTFZzH"
	sequence := uint32(1)
	amount := uint64(2000000000)
	fee := uint64(10000)
	lastLedgerSequence := uint32(353535)
	memoType := "client"
	memoData := "111"
	memoFormat := "text/plain"

	emptyTrans, hash, err := CreateEmptyRawTransactionAndHash(from, pubkey, sequence, to, amount, fee, lastLedgerSequence, memoType, memoData, memoFormat)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Println("empty transaction : \n", emptyTrans)
		fmt.Println("transaction hash  : \n", hash)
	}

	prikey, _ := hex.DecodeString("1acaaedece405b2a958212629e16f2eb46b153eee94cdd350fdeff52795525b7")
	signature, err := SignRawTransaction(hash, prikey)
	if err != nil {
		t.Error(err)
	} else {
		//signature = "168a76d7bef92f30761a03c0d039f9f018d32af756548f6e9ef41d1098d94ab5343513ca97f6437beca53b2e2ef36ee79a8fd2f4397473dd0031c12df11e6b83"
		fmt.Println("signature data : \n", signature)
	}

	//
	pass, signedTrans := VerifyAndCombinRawTransaction(emptyTrans, signature, pubkey)
	if pass {
		fmt.Println("signed transaction : \n", signedTrans)
	} else {
		t.Error("Verify transaction failed!")
	}
}
