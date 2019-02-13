package virtualeconomyTransaction

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func Test_case(t *testing.T) {
	amount := uint64(1000000000)
	fee := uint64(10000000)
	feeScale := uint16(100)
	to := "AU6GsBinGPqW8zUuvmjgwpBNLfyyTU3p83Q"
	attachment := ""

	// 构建结构体用于创建交易单
	ts := TxStruct{
		TxType:     TxTypeTransfer,
		To:         to,
		Amount:     amount,
		Fee:        fee,
		FeeScale:   feeScale,
		Attachment: attachment,
	}

	emptyTrans, err := CreateEmptyTransaction(ts)
	if err != nil {
		fmt.Println(err)
		t.Error("Failed to create empty raw transaction!")
	} else {
		fmt.Println(emptyTrans)
	}

	// emptyTrans 同时也是用于最终签名的值，该链不存在用于签名的哈希

	// 对空交易单进行签名
	prikey := []byte{0x18, 0x6f, 0xdc, 0x45, 0xdb, 0x17, 0x67, 0x2d, 0x00, 0x56, 0x22, 0x03, 0x8f, 0x4c, 0x9e, 0x1c, 0x42, 0x4a, 0xce, 0xe6, 0x61, 0x10, 0x8f, 0xc7, 0x0a, 0xde, 0xe9, 0xfb, 0x78, 0x71, 0xa5, 0x56}

	sigPub, err := SignTransaction(emptyTrans, prikey)
	if err != nil {
		fmt.Println(err)
		t.Error("Fail to sign transaction!")
	} else {
		fmt.Println("signature :")
		fmt.Println(hex.EncodeToString(sigPub.Signature))
		fmt.Println("public key :")
		fmt.Println(hex.EncodeToString(sigPub.PublicKey))
	}

	// 验证交易单签名
	// 该链不存在合并交易单操作
	pass := VerifyTransaction(emptyTrans, sigPub)
	if pass {
		fmt.Println("verify pass!")
	} else {
		t.Error("verify failed!")
	}

	// 构建用于发送交易单时的RPC接口的"POST"方法的json体字符串
	json, err := CreateJSONRawForSendTransaction(emptyTrans, sigPub)

	if err != nil {
		t.Error("create json failed!")
	} else {
		fmt.Println("JSON for send transaction!")
		fmt.Println(json)
	}

	// 用节点API的 /vsys/broadcast/payment POST以上json 即可发送该笔交易
}
