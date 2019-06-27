package waykichainTransaction

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func Test_register_account(t *testing.T) {
	publicKey := "02798c0f8319260879303b5059efb3fdb057517c8e3d0fcccc627b4bb92c34d35d"
	privateKey := []byte{0x98, 0x8c, 0x6b, 0x6d, 0xdc, 0xd4, 0xd1, 0x01, 0xc8, 0x27, 0x9d, 0x27, 0x89, 0x02, 0x46, 0x66, 0x4b, 0x65, 0x35, 0xea, 0x2f, 0x27, 0x8a, 0x8c, 0x8d, 0x6f, 0xd5, 0x19, 0xf1, 0x4a, 0xe7, 0x7b}
	validHeight := int64(7783)
	fee := int64(10000)

	// 创建注册交易单与哈希
	emptyTrans, hash, err := CreateEmptyRawTransactionAndHash(publicKey, "", "", 0, fee, validHeight, TxType_REGACCT)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Println("空交易单:\n", emptyTrans)
		fmt.Println("待签哈希:\n", hash)
	}

	// 交易单签名
	signature, err := SignRawTransaction(hash, privateKey)
	if err != nil {
		t.Error(err)
	} else {
		signature, _ = hex.DecodeString("2ed0f0def4deca6fcf4836a426353f88e009248814f8e5189b83ec36514252c00149ee123aac2b56784244529498021ee9b0301d105538c8b4608a46e18c660e")
		fmt.Println("签名结果:\n", hex.EncodeToString(signature))
	}

	//验签与交易单合并
	sigPub := SigPub{
		PublicKey: []byte{0x02, 0x79, 0x8c, 0x0f, 0x83, 0x19, 0x26, 0x08, 0x79, 0x30, 0x3b, 0x50, 0x59, 0xef, 0xb3, 0xfd, 0xb0, 0x57, 0x51, 0x7c, 0x8e, 0x3d, 0x0f, 0xcc, 0xcc, 0x62, 0x7b, 0x4b, 0xb9, 0x2c, 0x34, 0xd3, 0x5d},
		Signature: signature,
	}
	pass, signedTrans := VerifyAndCombineRawTransaction(emptyTrans, sigPub)
	if !pass {
		t.Error("verify failed!")
	} else {
		if signedTrans != "0201bb672102798c0f8319260879303b5059efb3fdb057517c8e3d0fcccc627b4bb92c34d35d00cd1046304402202ed0f0def4deca6fcf4836a426353f88e009248814f8e5189b83ec36514252c002200149ee123aac2b56784244529498021ee9b0301d105538c8b4608a46e18c660e" {
			t.Error("transaction raw hex wrong!")
		}

		fmt.Println("合并之后的交易单:\n", signedTrans)
	}
}

func Test_common_tx(t *testing.T) {
	privateKey := []byte{0x51, 0x13, 0x04, 0x41, 0xa8, 0x97, 0xa5, 0xd5, 0xd0, 0xb1, 0x22, 0x55, 0x09, 0x2f, 0xba, 0xa3, 0x73, 0x75, 0x24, 0xd6, 0x05, 0xd6, 0x5a, 0xaa, 0x71, 0x83, 0x54, 0xef, 0x8a, 0x5f, 0x41, 0x70}
	publicKey := []byte{0x02, 0x1a, 0x37, 0x2d, 0x30, 0xd2, 0xe8, 0x45, 0x96, 0xad, 0x7c, 0x36, 0x13, 0x19, 0x7c, 0x27, 0x36, 0xb0, 0xa1, 0xe4, 0x1e, 0x36, 0xb5, 0xe9, 0x59, 0x8a, 0x5d, 0x1e, 0x97, 0x84, 0x39, 0xbe, 0x9b}
	validHeight := int64(14897)
	fromUserID := "158-1"
	ToAddress := "WbP5WTty9jz6tAsAXwJMAinURp8fFdbDwL"
	amount := int64(10000)
	fee := int64(10000)

	// 构建交易单和哈希
	emptyTrans, hash, err := CreateEmptyRawTransactionAndHash(fromUserID, ToAddress, "", amount, fee, validHeight, TxType_COMMON)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Println("空交易单:\n", emptyTrans)
		fmt.Println("待签哈希:\n", hash)
	}

	// 交易单签名
	signature, err := SignRawTransaction(hash, privateKey)
	if err != nil {
		t.Error(err)
	} else {
		//signature, _ = hex.DecodeString("2c0016b98229a160c4219469b67d81ee1c01bc83f467161d83ebddcfa72c0daf578a3af264847f4f942f4082c073dd578b3576bf25b96e8f48a97dd5a98e2b00")
		fmt.Println("签名结果:\n", hex.EncodeToString(signature))
	}

	//验签与交易单合并
	sigPub := SigPub{
		PublicKey: publicKey,
		Signature: signature,
	}
	pass, signedTrans := VerifyAndCombineRawTransaction(emptyTrans, sigPub)
	if !pass {
		t.Error("verify failed!")
	} else {
		// if signedTrans != "0301f33103801e01144abc43807e950927431390c3cf9a0d3f20c8c5c3cd10cd100046304402202c0016b98229a160c4219469b67d81ee1c01bc83f467161d83ebddcfa72c0daf0220578a3af264847f4f942f4082c073dd578b3576bf25b96e8f48a97dd5a98e2b00" {
		// 	t.Error("transaction raw hex wrong!")
		// }

		fmt.Println("合并之后的交易单:\n", signedTrans)
	}
}

func Test_call_contract(t *testing.T) {
	privateKey, _ := hex.DecodeString("988c6b6ddcd4d101c8279d27890246664b6535ea2f278a8c8d6fd519f14ae77b")
	publicKey, _ := hex.DecodeString("02798c0f8319260879303b5059efb3fdb057517c8e3d0fcccc627b4bb92c34d35d")
	validHeight := int64(22365)
	fromUserID := "7849-1"
	appID := "20988-1"
	fee := int64(100000)
	amount := int64(10000)
	contractHex := "f017"
	// 构建交易单和哈希
	emptyTrans, hash, err := CreateEmptyRawTransactionAndHash(fromUserID, contractHex, appID, amount, fee, validHeight, TxType_CONTRACT)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Println("空交易单:\n", emptyTrans)
		fmt.Println("待签哈希:\n", hash)
	}
	// 交易单签名
	signature, err := SignRawTransaction(hash, privateKey)
	if err != nil {
		t.Error(err)
	} else {
		signature, _ = hex.DecodeString("288cf9698f3fb4fb1257110c31f72f4b288ee4efcbebc15e55f39fe604d45b1162bec5e0fbc4e5112cd438bf2a0afff125592f2dfc95a9dac69d767982221e25")
		fmt.Println("签名结果:\n", hex.EncodeToString(signature))
	}

	//验签与交易单合并
	sigPub := SigPub{
		PublicKey: publicKey,
		Signature: signature,
	}
	pass, signedTrans := VerifyAndCombineRawTransaction(emptyTrans, sigPub)
	if !pass {
		t.Error("verify failed!")
	} else {
		// if signedTrans != "0301f33103801e01144abc43807e950927431390c3cf9a0d3f20c8c5c3cd10cd100046304402202c0016b98229a160c4219469b67d81ee1c01bc83f467161d83ebddcfa72c0daf0220578a3af264847f4f942f4082c073dd578b3576bf25b96e8f48a97dd5a98e2b00" {
		// 	t.Error("transaction raw hex wrong!")
		// }

		fmt.Println("合并之后的交易单:\n", signedTrans)
	}
}
