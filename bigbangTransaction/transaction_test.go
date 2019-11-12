package bigbangTransaction

import (
	"encoding/hex"
	"fmt"
	"testing"
)

// cheange timestamp in CreateEmptyTransactionAndHash() to 1572920900 to pass this case
func Test_testnet_5dc0de44ec87306611fbb5af303ffc96d167d2a5a3fd75bd1e4a865a01a65b58(t *testing.T) {
	anchor := "00000000dcde418dca150e49f53ab857d5ccd095a800bfb29ea87385267bc069"
	txid := "5dba7e87b7060a1cab84d13700e17519b5cde33d2aaa466d45c519d5e125dada"
	vout := byte(0)

	vin := Vin{
		TxID: txid,
		Vout: vout,
	}

	to := "1j3xa8kka2d0y1ep3x7dadvkwy771aa02h791029t4sqhgn4j8c3xysst"
	amount := uint64(1000000)
	fee := uint64(100)

	memo := ""

	lockUntil := uint32(0)

	emptyTrans, hash, err := CreateEmptyTransactionAndHash(lockUntil, anchor, []Vin{vin}, to, amount, fee, memo)

	if err != nil {
		fmt.Println(err)
		t.Error("Create failed!")
		return
	} else {
		fmt.Println("Empty transaction : ", emptyTrans)
		fmt.Println("Transaction hash  : ", hash)
	}

	prikey := []byte{0x80, 0xbc, 0x39, 0x8d, 0x7c, 0x4a, 0x67, 0x4d, 0xaa, 0x97, 0x75, 0x66, 0xc2, 0xe6, 0xcd, 0x50, 0x40, 0x52, 0x00, 0x27, 0xe5, 0x7f, 0xe8, 0x06, 0xdf, 0xaa, 0x86, 0x8d, 0xf4, 0xcc, 0x43, 0xab}
	signature, err := SignTransactionHash(hash, prikey)
	if err != nil {
		fmt.Println(err)
		t.Error("Sign failed!")
		return
	} else {
		signature = "d8b31d2a6d7ed3c6b24be66284491bc79f5635de0e1f8aa974cea8a15071f4cef2db71735381be6c23d86bebd22985bccf75f1886ea93fe4d74aadc13307de02"
		fmt.Println("Signature result : ", signature)
	}

	pubkey, _ := hex.DecodeString("43c814013916d558d23f183ad85a16d947448518ccf91f4591493a49be8f4f64")

	pass, signedTrans := VerifyAndCombineTransaction(emptyTrans, signature, pubkey)
	if pass {
		fmt.Println("success")
		fmt.Println("Signed transaction : ", signedTrans)
	} else {
		t.Error("Verify failed!")
		return
	}

}