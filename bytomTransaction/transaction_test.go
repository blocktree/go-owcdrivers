package bytomTransaction

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/blocktree/go-owcrypt"
)

// 案例一
// BTM资产
// from P2WPKH to P2WPKH
// 单个UTXO向单个地址支付
func Test_case1(t *testing.T) {
	// 获取UTXO信息
	sourceID := "1111111111111111111111111111111111111111111111111111111111111111"
	sourcePos := uint64(0)
	assetID := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	amount := uint64(1000000000)
	controlProgram := "0014424e09458108aa7b871bc265ae5236545c3d3129"

	// 构建输入
	in := Vin{sourceID, sourcePos, assetID, amount, controlProgram}

	// 目标地址与数额
	address := "bm1q2vjdmpkwczwfh5fj208j3raunddktth8cglz4h"
	sendAmount := uint64(500000)

	// 构建输出
	out := Vout{address, sendAmount}

	// 设置timerange
	timeRange := uint64(0)

	// 构建空交易单
	emptyTrans, err := CreateEmptyRawTransaction([]Vin{in}, []Vout{out}, timeRange)

	if err != nil {
		t.Error("创建空交易单失败")
	} else {
		fmt.Println(emptyTrans)
	}

	// 获取交易单哈希
	txHash, err := CreateRawTransactionHashForSig(emptyTrans)

	if err != nil {
		fmt.Println(err)
		t.Error("获取交易单哈希失败")
	} else {
		fmt.Println("交易单哈希")
		fmt.Println(txHash[0].Hash)
	}

	prikey := []byte{0xB0, 0x54, 0xEE, 0x6F, 0x15, 0x23, 0x93, 0x19, 0x62, 0x23, 0xB3, 0xAF, 0x19, 0x3B, 0x8F, 0x6F, 0x62, 0x85, 0x55, 0xEC, 0xAE, 0x23, 0xF4, 0xCB, 0x1A, 0x49, 0x83, 0x7E, 0x06, 0xB9, 0x70, 0x5F}

	// 使用私钥对相应哈希值进行签名
	sigPub, err := SignRawTransactionHash(txHash[0].Hash, prikey)
	if err != nil {
		t.Error("签名失败！")
	} else {
		fmt.Println("signature:")
		fmt.Println(hex.EncodeToString(sigPub.Signature))
		fmt.Println("pubkey:")
		fmt.Println(hex.EncodeToString(sigPub.Pubkey))
	}

	// 将客户端返回的哈希值回填入TxHash结构体数组
	txHash[0].Normal.SigPub = *sigPub

	// 将签名结果插入空格交易单
	signedTrans, err := InsertSignatureIntoEmptyTransaction(emptyTrans, txHash)

	if err != nil {
		t.Error("插入失败")
	} else {
		fmt.Println("合并后的交易单:")
		fmt.Println(signedTrans)
	}

	// 交易单验证
	pass := VerifyRawTransaction(signedTrans)

	if pass {
		fmt.Println("验证通过")
	} else {
		t.Error("交易单验证失败")
	}
}

// 案例二
// BTM资产
// from P2WPKH to P2WPKH
// 多个UTXO向多个地址支付
func Test_case2(t *testing.T) {
	// 第一个UTXO
	sourceID1 := "1111111111111111111111111111111111111111111111111111111111111111"
	sourcePos1 := uint64(0)
	assetID1 := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	amount1 := uint64(1000000000)
	controlProgram1 := "0014424e09458108aa7b871bc265ae5236545c3d3129"

	in1 := Vin{sourceID1, sourcePos1, assetID1, amount1, controlProgram1}

	// 第二个UTXO
	sourceID2 := "2222222222222222222222222222222222222222222222222222222222222222"
	sourcePos2 := uint64(0)
	assetID2 := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	amount2 := uint64(2000000000)
	controlProgram2 := "00143fbd41b61e904b6049521c9548ca6a5a1953d803"

	in2 := Vin{sourceID2, sourcePos2, assetID2, amount2, controlProgram2}

	// 第一个输出
	address1 := "bm1q2vjdmpkwczwfh5fj208j3raunddktth8cglz4h"
	sendAmount1 := uint64(500000)

	out1 := Vout{address1, sendAmount1}

	// 第二个输出
	address2 := "bm1q2vjdmpkwczwfh5fj208j3raunddktthg89v720"
	sendAmount2 := uint64(800000)

	out2 := Vout{address2, sendAmount2}

	// 非0的交易timerange
	timeRange := uint64(654)

	// 构建空交易单
	emptyTrans, err := CreateEmptyRawTransaction([]Vin{in1, in2}, []Vout{out1, out2}, timeRange)

	if err != nil {
		t.Error("创建空交易单失败")
	} else {
		fmt.Println(emptyTrans)
	}

	// 获取交易单的签名哈希
	txHash, err := CreateRawTransactionHashForSig(emptyTrans)

	if err != nil {
		fmt.Println(err)
		t.Error("获取交易单哈希失败")
	} else {
		for i, v := range txHash {
			fmt.Println("第", i+1, "个交易单哈希")
			fmt.Println(v.Hash)
		}

	}

	prikey1 := []byte{0xB0, 0x54, 0xEE, 0x6F, 0x15, 0x23, 0x93, 0x19, 0x62, 0x23, 0xB3, 0xAF, 0x19, 0x3B, 0x8F, 0x6F, 0x62, 0x85, 0x55, 0xEC, 0xAE, 0x23, 0xF4, 0xCB, 0x1A, 0x49, 0x83, 0x7E, 0x06, 0xB9, 0x70, 0x5F}

	// 对交易单的第一个输入的哈希进行签名
	sigPub1, err := SignRawTransactionHash(txHash[0].Hash, prikey1)
	if err != nil {
		t.Error("签名失败！")
	} else {
		fmt.Println("第一个签名结果")
		fmt.Println("signature:")
		fmt.Println(hex.EncodeToString(sigPub1.Signature))
		fmt.Println("pubkey:")
		fmt.Println(hex.EncodeToString(sigPub1.Pubkey))
	}

	prikey2 := []byte{0xB0, 0x22, 0xEE, 0x6F, 0x15, 0x23, 0x93, 0x19, 0x62, 0x23, 0xB3, 0xAF, 0x19, 0x3B, 0x8F, 0x6F, 0x62, 0x85, 0x55, 0xEC, 0xAE, 0x23, 0xF4, 0xCB, 0x1A, 0x49, 0x83, 0x7E, 0x06, 0xB9, 0x70, 0x5F}

	// 对交易单的第二个输入的哈希签名
	sigPub2, err := SignRawTransactionHash(txHash[1].Hash, prikey2)
	if err != nil {
		t.Error("签名失败！")
	} else {
		fmt.Println("第二个签名结果")
		fmt.Println("signature:")
		fmt.Println(hex.EncodeToString(sigPub2.Signature))
		fmt.Println("pubkey:")
		fmt.Println(hex.EncodeToString(sigPub2.Pubkey))
	}

	// 将客户端返回的签名值回填入TxHash结构体数组
	txHash[0].Normal.SigPub = *sigPub1
	txHash[1].Normal.SigPub = *sigPub2

	// 将签名结果插入空交易单
	signedTrans, err := InsertSignatureIntoEmptyTransaction(emptyTrans, txHash)

	if err != nil {
		t.Error("插入失败")
	} else {
		fmt.Println("合并后的交易单:")
		fmt.Println(signedTrans)
	}

	// 交易单验证
	pass := VerifyRawTransaction(signedTrans)

	if pass {
		fmt.Println("验证通过")
	} else {
		t.Error("交易单验证失败")
	}
}

// 案例三 创建多重签名地址
func Test_case3(t *testing.T) {
	key1, _ := hex.DecodeString("a560f736c78313cf59007dab5de5804d22afded4345e34029b605412420b8831")
	key2, _ := hex.DecodeString("9f3b0af50d33ac7be238b9059783da7cc6ec71f56befd082a696509ecdce0609")
	required := byte(2)

	addressCHK := "bm1qxduz8fah8g2kz8q9lze4rnwtujy50325wmv082zsg7sxl08fs7zqz0kr08"
	signScriptCHK := "ae20a560f736c78313cf59007dab5de5804d22afded4345e34029b605412420b8831209f3b0af50d33ac7be238b9059783da7cc6ec71f56befd082a696509ecdce06095252ad"

	address, signScript, err := CreateMultiSig(required, [][]byte{key1, key2})

	if err != nil {
		t.Error("创建多签地址失败")
	} else {
		fmt.Println("地址: ", address)
		if address != addressCHK {
			t.Error("与预期结果不一致")
		}
		fmt.Println("赎回: ", signScript)
		if signScript != signScriptCHK {
			t.Error("与预期结果不一致")
		}

	}

}

// 案例四
// 花费多签的UTXO
func Test_case4(t *testing.T) {

	// 构建前置数据
	prikey1 := []byte{0xB0, 0x54, 0xEE, 0x6F, 0x15, 0x23, 0x93, 0x19, 0x62, 0x23, 0xB3, 0xAF, 0x19, 0x3B, 0x8F, 0x6F, 0x62, 0x85, 0x55, 0xEC, 0xAE, 0x23, 0xF4, 0xCB, 0x1A, 0x49, 0x83, 0x7E, 0x06, 0xB9, 0x70, 0x5F}
	prikey2 := []byte{0xB0, 0x22, 0xEE, 0x6F, 0x15, 0x23, 0x93, 0x19, 0x62, 0x23, 0xB3, 0xAF, 0x19, 0x3B, 0x8F, 0x6F, 0x62, 0x85, 0x55, 0xEC, 0xAE, 0x23, 0xF4, 0xCB, 0x1A, 0x49, 0x83, 0x7E, 0x06, 0xB9, 0x70, 0x5F}
	pubkey1 := owcrypt.Point_mulBaseG(prikey1, owcrypt.ECC_CURVE_ED25519)
	pubkey2 := owcrypt.Point_mulBaseG(prikey2, owcrypt.ECC_CURVE_ED25519)
	_, signScript, _ := CreateMultiSig(2, [][]byte{pubkey1, pubkey2})
	signScriptBytes, _ := hex.DecodeString(signScript)
	controlProgramBytes := owcrypt.Hash(signScriptBytes, 0, owcrypt.HASH_ALG_SHA3_256)

	//begine
	// 获取UTXO信息
	sourceID := "1111111111111111111111111111111111111111111111111111111111111111"
	sourcePos := uint64(0)
	assetID := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	amount := uint64(1000000000)
	controlProgram := "0020" + hex.EncodeToString(controlProgramBytes)

	// 构建输入
	in := Vin{sourceID, sourcePos, assetID, amount, controlProgram}

	// 目标地址与数额
	address := "bm1q2vjdmpkwczwfh5fj208j3raunddktth8cglz4h"
	sendAmount := uint64(500000)

	// 构建输出
	out := Vout{address, sendAmount}

	// 设置timerange
	timeRange := uint64(0)

	// 构建空交易单
	emptyTrans, err := CreateEmptyRawTransaction([]Vin{in}, []Vout{out}, timeRange)

	if err != nil {
		t.Error("创建空交易单失败")
	} else {
		fmt.Println(emptyTrans)
	}

	// 获取交易单哈希
	txHash, err := CreateRawTransactionHashForSig(emptyTrans)

	if err != nil {
		fmt.Println(err)
		t.Error("获取交易单哈希失败")
	} else {
		fmt.Println("交易单哈希")
		fmt.Println(txHash[0].Hash)
	}

	// 判断如果是多重签名哈希的话，需要使用signScript对哈希结构体进行pad
	if txHash[0].IsMultiSig() {
		if nil != txHash[0].PadMultiSig(signScript) {
			t.Error("填充多签数据失败")
		}
		if txHash[0].NRequired != 2 || hex.EncodeToString(pubkey1) != txHash[0].Multi[0].Pubkey || hex.EncodeToString(pubkey2) != txHash[0].Multi[1].Pubkey {
			t.Error("填充结果错误")
		}
	}

	// 使用第一个私钥对哈希值签名
	sigPub1, err := SignRawTransactionHash(txHash[0].Hash, prikey1)
	if err != nil {
		t.Error("签名失败！")
	} else {
		fmt.Println("第一个:")
		fmt.Println("signature:")
		fmt.Println(hex.EncodeToString(sigPub1.Signature))
		fmt.Println("pubkey:")
		fmt.Println(hex.EncodeToString(sigPub1.Pubkey))
	}

	// 使用第二个私钥对哈希值签名
	sigPub2, err := SignRawTransactionHash(txHash[0].Hash, prikey2)
	if err != nil {
		t.Error("签名失败！")
	} else {
		fmt.Println("第二个:")
		fmt.Println("signature:")
		fmt.Println(hex.EncodeToString(sigPub2.Signature))
		fmt.Println("pubkey:")
		fmt.Println(hex.EncodeToString(sigPub2.Pubkey))
	}

	// 将客户端返回的哈希值回填入TxHash结构体数组
	txHash[0].Multi[0].SigPub = *sigPub1
	txHash[0].Multi[1].SigPub = *sigPub2

	// 将签名结果插入空格交易单
	signedTrans, err := InsertSignatureIntoEmptyTransaction(emptyTrans, txHash)

	if err != nil {
		t.Error("插入失败")
	} else {
		fmt.Println("合并后的交易单:")
		fmt.Println(signedTrans)
	}

	// 交易单验证
	// pass := VerifyRawTransaction(signedTrans)

	// if pass {
	// 	fmt.Println("验证通过")
	// } else {
	// 	t.Error("交易单验证失败")
	// }
}
