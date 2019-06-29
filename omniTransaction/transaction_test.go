package omniTransaction

import (
	"encoding/hex"
	"fmt"
	"testing"
)

// 案例一
// simple send
// from p2pkh
// to p2pkh
// 1 in 1 out (无找零)
func Test_case1(t *testing.T) {
	// 输入
	in := Vin{"6cb0425bb4bb962db8359b8d3cbaa66ed8121091db6cfc9253f5bf1e9cef604f", uint32(0)}

	// 目标地址与数额
	// 向 mwmXzRM19gg5AB5Vu16dvfuhWujTq5PzvK 发送
	// out 单位为聪
	to := Vout{"mwmXzRM19gg5AB5Vu16dvfuhWujTq5PzvK", uint64(200)}

	// USDT 发送的详细数据
	// simple send模式需要指定的数据有：
	// TxType = SimpleSend
	// PropertyID = DefaultTetherUSID
	// Amoungt = 50000000000
	omniDetail := OmniStruct{SimpleSend, DefaultTetherUSID, 50000000000, 0, "", ""}

	//锁定时间
	lockTime := uint32(0)

	//追加手续费支持
	replaceable := false

	/////////构建空交易单
	emptyTrans, err := CreateEmptyRawTransaction([]Vin{in}, []Vout{to}, omniDetail, lockTime, replaceable, BTCTestnetAddressPrefix)
	if err != nil {
		t.Error("构建空交易单失败")
	} else {
		fmt.Println("空交易单：")
		fmt.Println(emptyTrans)
	}

	// 获取in的锁定脚本
	// 填充TxUnlock结构体
	inLock := "76a914d46043209073ad39879356295562d952cd9dae3a88ac"
	//针对此类指向公钥哈希地址的UTXO，此处仅需要锁定脚本即可计算待签交易单
	unlockData := TxUnlock{inLock, "", uint64(0), SigHashAll}

	////////构建用于签名的交易单哈希
	transHash, err := CreateRawTransactionHashForSig(emptyTrans, []TxUnlock{unlockData}, BTCTestnetAddressPrefix)
	if err != nil {
		t.Error("获取待签名交易单哈希失败")
	} else {
		for i, t := range transHash {
			fmt.Println("第", i+1, "个交易单哈希值为")
			fmt.Println(t)
		}
	}

	//将交易单哈希与每条哈希对应的地址发送给客户端
	//客户端根据对应地址派生私钥对哈希进行签名

	// 获取私钥
	// in address mzsts8xiVWv8uGEYUrAB6XzKXZPiX9j6jq
	inPrikey := []byte{0x80, 0xbc, 0x39, 0x8d, 0x7c, 0x4a, 0x67, 0x4d, 0xaa, 0x97, 0x75, 0x66, 0xc2, 0xe6, 0xcd, 0x50, 0x40, 0x52, 0x00, 0x27, 0xe5, 0x7f, 0xe8, 0x06, 0xdf, 0xaa, 0x86, 0x8d, 0xf4, 0xcc, 0x43, 0xab}

	// 客户端对第一条hash进行签名
	sigPub, err := SignRawTransactionHash(transHash[0].Hash, inPrikey)
	if err != nil {
		t.Error("hash签名失败!")
	} else {
		fmt.Println("hash签名结果")
		fmt.Println(hex.EncodeToString(sigPub.Signature))
		fmt.Println("对应公钥")
		fmt.Println(hex.EncodeToString(sigPub.Pubkey))
	}

	// 服务器收到签名结果后，使用签名结果填充TxHash结构体
	transHash[0].Normal.SigPub = *sigPub

	//回填后，将签名插入空交易单
	signedTrans, err := InsertSignatureIntoEmptyTransaction(emptyTrans, transHash, []TxUnlock{unlockData})
	if err != nil {
		t.Error("插入交易单失败")
	} else {
		fmt.Println("合并之后的交易单")
		fmt.Println(signedTrans)
	}

	// 验证交易单
	pass := VerifyRawTransaction(signedTrans, []TxUnlock{unlockData}, BTCTestnetAddressPrefix)
	if pass {
		fmt.Println("验证通过!")
	} else {
		t.Error("验证失败!")
	}
}

// 案例二
// simple send
// from p2pkh
// to p2pkh
// 2 in 2 out (找零)
func Test_case2(t *testing.T) {
	// 第一个输入
	in1 := Vin{"6cb0425bb4bb962db8359b8d3cbaa66ed8121091db6cfc9253f5bf1e9cef604f", uint32(0)}
	// 第二个输入
	in2 := Vin{"24cf52fb9588acf6a8413cd914532e27b5b376a6ebdbc98150cda76e1ae92b67", uint32(0)}

	// 目标地址与数额
	// 向 mwmXzRM19gg5AB5Vu16dvfuhWujTq5PzvK 发送
	// out 单位为聪
	to := Vout{"mwmXzRM19gg5AB5Vu16dvfuhWujTq5PzvK", uint64(2000000)}
	change := Vout{"mwmXzRM19gg5AB5Vu16dvfuhWujTq5PzvK", uint64(200)}

	omniDetail := OmniStruct{SimpleSend, DefaultTetherUSID, 50000000000, 0, "", ""}
	//锁定时间
	lockTime := uint32(0)

	//追加手续费支持
	replaceable := false

	/////////构建空交易单
	emptyTrans, err := CreateEmptyRawTransaction([]Vin{in1, in2}, []Vout{to, change}, omniDetail, lockTime, replaceable, BTCTestnetAddressPrefix)

	if err != nil {
		t.Error("构建空交易单失败")
	} else {
		fmt.Println("空交易单：")
		fmt.Println(emptyTrans)
	}

	// 获取in1 和 in2 的锁定脚本
	// 填充TxUnlock结构体
	in1Lock := "76a914d46043209073ad39879356295562d952cd9dae3a88ac"
	in2Lock := "76a914d46043209073ad39879356295562d952cd9dae3a88ac"

	//针对此类指向公钥哈希地址的UTXO，此处仅需要锁定脚本即可计算待签交易单
	unlockData1 := TxUnlock{in1Lock, "", uint64(0), SigHashAll}
	unlockData2 := TxUnlock{in2Lock, "", uint64(0), SigHashAll}

	////////构建用于签名的交易单哈希
	transHash, err := CreateRawTransactionHashForSig(emptyTrans, []TxUnlock{unlockData1, unlockData2}, BTCTestnetAddressPrefix)
	if err != nil {
		t.Error("获取待签名交易单哈希失败")
	} else {
		for i, t := range transHash {
			fmt.Println("第", i+1, "个交易单哈希值为")
			fmt.Println(t)
		}
	}

	//将交易单哈希与每条哈希对应的地址发送给客户端
	//客户端根据对应地址派生私钥对哈希进行签名

	// 获取私钥
	// in1 address mzsts8xiVWv8uGEYUrAB6XzKXZPiX9j6jq
	in1Prikey := []byte{0x80, 0xbc, 0x39, 0x8d, 0x7c, 0x4a, 0x67, 0x4d, 0xaa, 0x97, 0x75, 0x66, 0xc2, 0xe6, 0xcd, 0x50, 0x40, 0x52, 0x00, 0x27, 0xe5, 0x7f, 0xe8, 0x06, 0xdf, 0xaa, 0x86, 0x8d, 0xf4, 0xcc, 0x43, 0xab}
	// in2 address mzsts8xiVWv8uGEYUrAB6XzKXZPiX9j6jq
	in2Prikey := []byte{0x80, 0xbc, 0x39, 0x8d, 0x7c, 0x4a, 0x67, 0x4d, 0xaa, 0x97, 0x75, 0x66, 0xc2, 0xe6, 0xcd, 0x50, 0x40, 0x52, 0x00, 0x27, 0xe5, 0x7f, 0xe8, 0x06, 0xdf, 0xaa, 0x86, 0x8d, 0xf4, 0xcc, 0x43, 0xab}

	// 客户端对第一条hash进行签名
	sigPub1, err := SignRawTransactionHash(transHash[0].Hash, in1Prikey)
	if err != nil {
		t.Error("第一条hash签名失败!")
	} else {
		fmt.Println("第一条hash签名结果")
		fmt.Println(hex.EncodeToString(sigPub1.Signature))
		fmt.Println("对应公钥")
		fmt.Println(hex.EncodeToString(sigPub1.Pubkey))
	}

	// 客户端对第二条hash进行签名
	sigPub2, err := SignRawTransactionHash(transHash[1].Hash, in2Prikey)
	if err != nil {
		t.Error("第二条hash签名失败!")
	} else {
		fmt.Println("第二条hash签名结果")
		fmt.Println(hex.EncodeToString(sigPub2.Signature))
		fmt.Println("对应公钥")
		fmt.Println(hex.EncodeToString(sigPub2.Pubkey))
	}

	// 服务器收到签名结果后，使用签名结果填充TxHash结构体
	transHash[0].Normal.SigPub = *sigPub1
	transHash[1].Normal.SigPub = *sigPub2

	//回填后，将签名插入空交易单
	signedTrans, err := InsertSignatureIntoEmptyTransaction(emptyTrans, transHash, []TxUnlock{unlockData1, unlockData2})
	if err != nil {
		t.Error("插入交易单失败")
	} else {
		fmt.Println("合并之后的交易单")
		fmt.Println(signedTrans)
	}

	// 验证交易单
	pass := VerifyRawTransaction(signedTrans, []TxUnlock{unlockData1, unlockData2}, BTCTestnetAddressPrefix)
	if pass {
		fmt.Println("验证通过!")
	} else {
		t.Error("验证失败!")
	}
}

//案例三
// simple send
// from 多签地址
// to p2pkh
// 1 in 1 out (无找零)
func Test_case10(t *testing.T) {
	// step1
	// 创建多重签名地址

	// 2 of  3
	required := byte(2)
	// 获取来自三方的公钥，可为压缩或不压缩格式
	pubA := []byte{0x02, 0x9F, 0xC3, 0x70, 0xE6, 0x31, 0x59, 0xC0, 0x2C, 0x8E, 0x4A, 0x40, 0xCA, 0xE2, 0xFF, 0xB7, 0xBE, 0xE0, 0x60, 0xF4, 0x5A, 0xA9, 0x5C, 0x2B, 0x92, 0xAC, 0x11, 0x93, 0xE4, 0x3A, 0x0B, 0xB4, 0x77}
	pubB := []byte{0x03, 0xBA, 0x48, 0x38, 0xA4, 0x2D, 0x20, 0xE3, 0xED, 0x56, 0x3F, 0xCC, 0x87, 0x69, 0xE3, 0x54, 0xE7, 0x7D, 0x88, 0x35, 0x10, 0x4C, 0x92, 0x75, 0x85, 0x20, 0x38, 0x09, 0xB9, 0xD3, 0xBD, 0x9E, 0xA5}
	pubC := []byte{0x02, 0xC2, 0xE8, 0x65, 0xFC, 0x60, 0x17, 0x1F, 0x7F, 0xCD, 0xFB, 0xE8, 0xC2, 0x9A, 0xE4, 0x54, 0x46, 0x02, 0x56, 0xF3, 0xBA, 0xAD, 0x25, 0x34, 0x28, 0xE8, 0xD4, 0x0A, 0x37, 0x85, 0x2B, 0x38, 0x4A}

	//填充成为2维数组，获取多重签名地址
	address, redeem, err := CreateMultiSig(required, [][]byte{pubA, pubB, pubC}, BTCTestnetAddressPrefix)
	if err != nil {
		t.Error("创建多签地址失败！")
	} else {
		fmt.Println("地址为：")
		fmt.Println(address)
		fmt.Println("赎回脚本为：")
		fmt.Println(redeem)
	}

	//step 2
	// 向该多重签名地址转入一定数额的比特币
	//txid 511bac90d2fe072e736d8b58161f34da631526508754febe263c40e3ce4e4b10
	//vout 0
	//amount 0.1 BTC
	//ScriptPubkey a91499e0a93cb94891dd071639d7e2bdcd4b3c7df1f587

	//step3
	// 构建空交易单
	in := Vin{"511bac90d2fe072e736d8b58161f34da631526508754febe263c40e3ce4e4b10", uint32(0)}
	out := Vout{"mwmXzRM19gg5AB5Vu16dvfuhWujTq5PzvK", uint64(9800000)}

	// USDT 发送的详细数据
	// simple send模式需要指定的数据有：
	// TxType = SimpleSend
	// PropertyID = DefaultTetherUSID
	// Amoungt = 50000000000
	omniDetail := OmniStruct{SimpleSend, DefaultTetherUSID, 50000000000, 0, "", ""}
	//锁定时间
	lockTime := uint32(0)

	//追加手续费支持
	replaceable := false

	emptyTrans, err := CreateEmptyRawTransaction([]Vin{in}, []Vout{out}, omniDetail, lockTime, replaceable, BTCTestnetAddressPrefix)
	if err != nil {
		t.Error("构建空交易单失败")
	} else {
		fmt.Println("空交易单：")
		fmt.Println(emptyTrans)
	}

	// 构建交易单签名哈希
	inLock := "a91499e0a93cb94891dd071639d7e2bdcd4b3c7df1f587"
	inRedeem := redeem
	inAmount := uint64(10000000)

	unlockData := TxUnlock{inLock, inRedeem, inAmount, SigHashAll}

	/////////计算待签名交易单哈希
	transHash, err := CreateRawTransactionHashForSig(emptyTrans, []TxUnlock{unlockData}, BTCTestnetAddressPrefix)
	if err != nil {
		t.Error("创建待签交易单哈希失败")
	} else {
		for i, t := range transHash {
			fmt.Println("第", i+1, "个交易单哈希值为")
			fmt.Println(t)
		}
	}

	//////签名哈希
	// 获取到的transHash数组只有一个元素，该哈希值是所有多签参与方的签名哈希
	// 根据required值，选择足够数量的签名方，发送哈希值

	// A的私钥
	priA := []byte{0xc0, 0xfc, 0x3b, 0xda, 0xaf, 0x3b, 0x9f, 0x29, 0xe1, 0xc5, 0x61, 0xe1, 0xb8, 0x74, 0x03, 0x62, 0xe8, 0x67, 0xa8, 0x95, 0x22, 0x31, 0xe9, 0xe7, 0x6f, 0x4d, 0x23, 0x57, 0x2b, 0x40, 0x27, 0x95}
	// B的私钥
	priB := []byte{0x4a, 0x11, 0x66, 0x9e, 0xa6, 0x64, 0xea, 0x19, 0xb7, 0x02, 0x98, 0x34, 0xe5, 0x12, 0xa8, 0x46, 0x54, 0xef, 0x80, 0x0a, 0x71, 0x61, 0xbc, 0xd1, 0x31, 0xd2, 0xf4, 0x7b, 0xfc, 0x07, 0xc5, 0x2a}

	// A 签名
	sigPubA, err := SignRawTransactionHash(transHash[0].Hash, priA)
	if err != nil {
		t.Error("A签名失败")
	} else {
		fmt.Println("A的签名结果为")
		fmt.Println(hex.EncodeToString(sigPubA.Signature))
	}

	// B 签名
	sigPubB, err := SignRawTransactionHash(transHash[0].Hash, priB)
	if err != nil {
		t.Error("B签名失败")
	} else {
		fmt.Println("B的签名结果为")
		fmt.Println(hex.EncodeToString(sigPubB.Signature))
	}

	// 接收到签名结果后，回填TxHash结构体数组
	transHash[0].Multi[0].SigPub = *sigPubA
	transHash[0].Multi[1].SigPub = *sigPubB

	// 合并交易单
	signedTrans, err := InsertSignatureIntoEmptyTransaction(emptyTrans, transHash, []TxUnlock{unlockData})
	if err != nil {
		t.Error("插入交易单失败")
	} else {
		fmt.Println("合并之后的交易单")
		fmt.Println(signedTrans)
	}

	// 验证交易单
	pass := VerifyRawTransaction(signedTrans, []TxUnlock{unlockData}, BTCTestnetAddressPrefix)
	if pass {
		fmt.Println("验证通过!")
	} else {
		t.Error("验证失败!")
	}
}

// 案例四
// send all
// from p2pkh
// to p2pkh
// 1 in 1 out
func Test_case4(t *testing.T) {
	// 输入
	in := Vin{"6cb0425bb4bb962db8359b8d3cbaa66ed8121091db6cfc9253f5bf1e9cef604f", uint32(0)}

	// 目标地址与数额
	// 向 mwmXzRM19gg5AB5Vu16dvfuhWujTq5PzvK 发送
	// out 单位为聪
	to := Vout{"mwmXzRM19gg5AB5Vu16dvfuhWujTq5PzvK", uint64(200)}

	// USDT 发送的详细数据
	// simple send模式需要指定的数据有：
	// TxType = SendAll
	// Ecosystem = DefaultEcoSystem
	omniDetail := OmniStruct{SendAll, 0, 0, DefaultEcoSystem, "", ""}

	//锁定时间
	lockTime := uint32(0)

	//追加手续费支持
	replaceable := false

	/////////构建空交易单
	emptyTrans, err := CreateEmptyRawTransaction([]Vin{in}, []Vout{to}, omniDetail, lockTime, replaceable, BTCTestnetAddressPrefix)
	if err != nil {
		t.Error("构建空交易单失败")
	} else {
		fmt.Println("空交易单：")
		fmt.Println(emptyTrans)
	}

	// 获取in的锁定脚本
	// 填充TxUnlock结构体
	inLock := "76a914d46043209073ad39879356295562d952cd9dae3a88ac"
	//针对此类指向公钥哈希地址的UTXO，此处仅需要锁定脚本即可计算待签交易单
	unlockData := TxUnlock{inLock, "", uint64(0), SigHashAll}

	////////构建用于签名的交易单哈希
	transHash, err := CreateRawTransactionHashForSig(emptyTrans, []TxUnlock{unlockData}, BTCTestnetAddressPrefix)
	if err != nil {
		t.Error("获取待签名交易单哈希失败")
	} else {
		for i, t := range transHash {
			fmt.Println("第", i+1, "个交易单哈希值为")
			fmt.Println(t)
		}
	}

	//将交易单哈希与每条哈希对应的地址发送给客户端
	//客户端根据对应地址派生私钥对哈希进行签名

	// 获取私钥
	// in address mzsts8xiVWv8uGEYUrAB6XzKXZPiX9j6jq
	inPrikey := []byte{0x80, 0xbc, 0x39, 0x8d, 0x7c, 0x4a, 0x67, 0x4d, 0xaa, 0x97, 0x75, 0x66, 0xc2, 0xe6, 0xcd, 0x50, 0x40, 0x52, 0x00, 0x27, 0xe5, 0x7f, 0xe8, 0x06, 0xdf, 0xaa, 0x86, 0x8d, 0xf4, 0xcc, 0x43, 0xab}

	// 客户端对第一条hash进行签名
	sigPub, err := SignRawTransactionHash(transHash[0].Hash, inPrikey)
	if err != nil {
		t.Error("hash签名失败!")
	} else {
		fmt.Println("hash签名结果")
		fmt.Println(hex.EncodeToString(sigPub.Signature))
		fmt.Println("对应公钥")
		fmt.Println(hex.EncodeToString(sigPub.Pubkey))
	}

	// 服务器收到签名结果后，使用签名结果填充TxHash结构体
	transHash[0].Normal.SigPub = *sigPub

	//回填后，将签名插入空交易单
	signedTrans, err := InsertSignatureIntoEmptyTransaction(emptyTrans, transHash, []TxUnlock{unlockData})
	if err != nil {
		t.Error("插入交易单失败")
	} else {
		fmt.Println("合并之后的交易单")
		fmt.Println(signedTrans)
	}

	// 验证交易单
	pass := VerifyRawTransaction(signedTrans, []TxUnlock{unlockData}, BTCTestnetAddressPrefix)
	if pass {
		fmt.Println("验证通过!")
	} else {
		t.Error("验证失败!")
	}
}

func Test_tmp(t *testing.T) {

	for index := 0; index < 1000; index++ {

		// 第一个输入
		in1 := Vin{"559a5e68b43b3bb7272e69203e43f82d922d5be4251013f5333daf0bb30cc2c3", uint32(0)}
		// 第二个输入
		in2 := Vin{"5fde0a6f7615668a20a82cadbadae6a88d219190dc3d30c5441145d8a9341bc4", uint32(0)}

		// 目标地址与数额
		// 向 mwmXzRM19gg5AB5Vu16dvfuhWujTq5PzvK 发送
		// out 单位为聪
		to := Vout{"1BhPgfzoNqoUeWniegWhgbqPuf9vnCrVGH", uint64(932788)}
		change := Vout{"12kSR8J11Q1d8JiYwZn7DZsPoDoptME35y", uint64(546)}

		omniDetail := OmniStruct{SimpleSend, MainTetherUS_01, 100000000, 0, "", ""}
		//锁定时间
		lockTime := uint32(0)

		//追加手续费支持
		replaceable := false

		/////////构建空交易单
		emptyTrans, err := CreateEmptyRawTransaction([]Vin{in1, in2}, []Vout{to, change}, omniDetail, lockTime, replaceable, BTCMainnetAddressPrefix)

		if err != nil {
			t.Error("构建空交易单失败")
		} else {
			fmt.Println("空交易单：")
			fmt.Println(emptyTrans)
		}

		// 获取in1 和 in2 的锁定脚本
		// 填充TxUnlock结构体
		in2Lock := "76a9147554d4fb989c873b8e84da7197b728086e9c6f5688ac"
		in1Lock := "76a914cc6e682fb54b5383e83bb72ecff67b78fbc0376b88ac"

		//针对此类指向公钥哈希地址的UTXO，此处仅需要锁定脚本即可计算待签交易单
		unlockData1 := TxUnlock{in1Lock, "", uint64(0), SigHashAll}
		unlockData2 := TxUnlock{in2Lock, "", uint64(0), SigHashAll}

		////////构建用于签名的交易单哈希
		transHash, err := CreateRawTransactionHashForSig(emptyTrans, []TxUnlock{unlockData1, unlockData2}, BTCMainnetAddressPrefix)
		if err != nil {
			t.Error("获取待签名交易单哈希失败")
		} else {
			for i, t := range transHash {
				fmt.Println("第", i+1, "个交易单哈希值为")
				fmt.Println(t)
			}
		}

		//将交易单哈希与每条哈希对应的地址发送给客户端
		//客户端根据对应地址派生私钥对哈希进行签名

		// 获取私钥
		// in1 address mzsts8xiVWv8uGEYUrAB6XzKXZPiX9j6jq
		in1Prikey := []byte{0x80, 0xbc, 0x39, 0x8d, 0x7c, 0x4a, 0x67, 0x4d, 0xaa, 0x97, 0x75, 0x66, 0xc2, 0xe6, 0xcd, 0x50, 0x40, 0x52, 0x00, 0x27, 0xe5, 0x7f, 0xe8, 0x06, 0xdf, 0xaa, 0x86, 0x8d, 0xf4, 0xcc, 0x43, 0xab}
		// in2 address mzsts8xiVWv8uGEYUrAB6XzKXZPiX9j6jq
		in2Prikey := []byte{0x80, 0xbc, 0x39, 0x8d, 0x7c, 0x4a, 0x67, 0x4d, 0xaa, 0x97, 0x75, 0x66, 0xc2, 0xe6, 0xcd, 0x50, 0x40, 0x52, 0x00, 0x27, 0xe5, 0x7f, 0xe8, 0x06, 0xdf, 0xaa, 0x86, 0x8d, 0xf4, 0xcc, 0x43, 0xab}

		// 客户端对第一条hash进行签名
		sigPub1, err := SignRawTransactionHash(transHash[0].Hash, in1Prikey)
		if err != nil {
			t.Error("第一条hash签名失败!")
		} else {
			fmt.Println("第一条hash签名结果")
			sigPub1.Signature, _ = hex.DecodeString("a2d71aa4dff5388af4090640b164a63fbfae41d3d57815c254ba8868301505185b9dcf8f047b5c042afea9e4e23202257b25c48860dca2b85d4bef6c64acafc0")
			sigPub1.Pubkey, _ = hex.DecodeString("02625778b063d342da349e74267de081a2588079bd01f9d38c6a57b4254ca6dd68")
			fmt.Println(hex.EncodeToString(sigPub1.Signature))
			fmt.Println("对应公钥")
			fmt.Println(hex.EncodeToString(sigPub1.Pubkey))
		}

		// 客户端对第二条hash进行签名
		sigPub2, err := SignRawTransactionHash(transHash[1].Hash, in2Prikey)
		if err != nil {
			t.Error("第二条hash签名失败!")
		} else {
			sigPub2.Signature, _ = hex.DecodeString("3fc9569c26b4638f01d328216931037e1e3eca7f34a9c462fe200abeebfcf1e60fae21bf9187cd4ed2703f8fd85c112c9f710d610bafee7d3e03774660525e18")
			sigPub2.Pubkey, _ = hex.DecodeString("0338db5069514e65bb4bf8c52d5b94d9f70ebdff659965d610e716c93fd3258c3a")

			fmt.Println("第二条hash签名结果")
			fmt.Println(hex.EncodeToString(sigPub2.Signature))
			fmt.Println("对应公钥")
			fmt.Println(hex.EncodeToString(sigPub2.Pubkey))
		}

		// 服务器收到签名结果后，使用签名结果填充TxHash结构体
		transHash[0].Normal.SigPub = *sigPub1
		transHash[1].Normal.SigPub = *sigPub2

		//回填后，将签名插入空交易单
		signedTrans, err := InsertSignatureIntoEmptyTransaction(emptyTrans, transHash, []TxUnlock{unlockData1, unlockData2})
		if err != nil {
			t.Error("插入交易单失败")
		} else {
			fmt.Println("合并之后的交易单")
			fmt.Println(signedTrans)
		}

		// 验证交易单
		pass := VerifyRawTransaction(signedTrans, []TxUnlock{unlockData1, unlockData2}, BTCMainnetAddressPrefix)
		if pass {
			fmt.Println("验证通过!")
		} else {
			t.Error("验证失败!")
		}
	}
}

// 案例二
// simple send
// from p2pkh
// to p2pkh
// 2 in 2 out (找零)
func Test_0_omni(t *testing.T) {
	// 第一个输入
	in1 := Vin{"e8183a262c288e6a445317a47bf803976c441fda8da3af10cd571fbc8805da11", uint32(0)} // 1MZZuJRkn4zA3VmDZPopzWZ7M9G3LqsXW3
	// 第二个输入
	in2 := Vin{"70b2cc3a50ed009030f976406aaff80fd5867b0fee9af1b227e1c0eb0f6d1ca9", uint32(0)} // 1BhPgfzoNqoUeWniegWhgbqPuf9vnCrVGH

	// 目标地址与数额
	// 向 mwmXzRM19gg5AB5Vu16dvfuhWujTq5PzvK 发送
	// out 单位为聪
	to := Vout{"1BhPgfzoNqoUeWniegWhgbqPuf9vnCrVGH", uint64(865606)}
	change := Vout{"12kSR8J11Q1d8JiYwZn7DZsPoDoptME35y", uint64(546)}

	omniDetail := OmniStruct{SimpleSend, MainTetherUS_01, 100000000, 0, "", ""}
	//锁定时间
	lockTime := uint32(0)

	//追加手续费支持
	replaceable := false

	/////////构建空交易单
	emptyTrans, err := CreateEmptyRawTransaction([]Vin{in1, in2}, []Vout{to, change}, omniDetail, lockTime, replaceable, BTCMainnetAddressPrefix)

	if err != nil {
		t.Error("构建空交易单失败")
	} else {
		fmt.Println("空交易单：")
		fmt.Println(emptyTrans)
	}

	// 获取in1 和 in2 的锁定脚本
	// 填充TxUnlock结构体
	in1Lock := "76a914e18b4a9b86c2fd36a5300e6ed9a6f901b3271b1988ac"
	in2Lock := "76a9147554d4fb989c873b8e84da7197b728086e9c6f5688ac"

	//针对此类指向公钥哈希地址的UTXO，此处仅需要锁定脚本即可计算待签交易单
	unlockData1 := TxUnlock{in1Lock, "", uint64(0), SigHashAll}
	unlockData2 := TxUnlock{in2Lock, "", uint64(0), SigHashAll}

	////////构建用于签名的交易单哈希
	transHash, err := CreateRawTransactionHashForSig(emptyTrans, []TxUnlock{unlockData1, unlockData2}, BTCMainnetAddressPrefix)
	if err != nil {
		t.Error("获取待签名交易单哈希失败")
	} else {
		for i, t := range transHash {
			fmt.Println("第", i+1, "个交易单哈希值为")
			fmt.Println(t)
		}
	}

	//将交易单哈希与每条哈希对应的地址发送给客户端
	//客户端根据对应地址派生私钥对哈希进行签名

	// 获取私钥
	// in1 address mzsts8xiVWv8uGEYUrAB6XzKXZPiX9j6jq
	in1Prikey := []byte{0x80, 0xbc, 0x39, 0x8d, 0x7c, 0x4a, 0x67, 0x4d, 0xaa, 0x97, 0x75, 0x66, 0xc2, 0xe6, 0xcd, 0x50, 0x40, 0x52, 0x00, 0x27, 0xe5, 0x7f, 0xe8, 0x06, 0xdf, 0xaa, 0x86, 0x8d, 0xf4, 0xcc, 0x43, 0xab}
	// in2 address mzsts8xiVWv8uGEYUrAB6XzKXZPiX9j6jq
	in2Prikey := []byte{0x80, 0xbc, 0x39, 0x8d, 0x7c, 0x4a, 0x67, 0x4d, 0xaa, 0x97, 0x75, 0x66, 0xc2, 0xe6, 0xcd, 0x50, 0x40, 0x52, 0x00, 0x27, 0xe5, 0x7f, 0xe8, 0x06, 0xdf, 0xaa, 0x86, 0x8d, 0xf4, 0xcc, 0x43, 0xab}

	// 客户端对第一条hash进行签名
	sigPub1, err := SignRawTransactionHash(transHash[0].Hash, in1Prikey)
	if err != nil {
		t.Error("第一条hash签名失败!")
	} else {
		sigPub1.Signature, _ = hex.DecodeString("f107e33eec69a3a98b7859857ea07e9e897c83b4b2f68699d72b32347cb0f9c7747984fe9647abb71e069913d85b2a817d0e8c4b8f130f6a12bdee881a005817")
		sigPub1.Pubkey, _ = hex.DecodeString("0290fa43d0af8dbf1cc7f0c04241c4a338e305feff7a86341507fe538e5d0e0a5e")

		fmt.Println("第一条hash签名结果")
		fmt.Println(hex.EncodeToString(sigPub1.Signature))
		fmt.Println("对应公钥")
		fmt.Println(hex.EncodeToString(sigPub1.Pubkey))
	}

	// 客户端对第二条hash进行签名
	sigPub2, err := SignRawTransactionHash(transHash[1].Hash, in2Prikey)
	if err != nil {
		t.Error("第二条hash签名失败!")
	} else {
		sigPub2.Signature, _ = hex.DecodeString("29a6222a71d5ce4b08c1d5e21fc6ab886cab39f12137f14afaaad9ba55dcaf6a1614d302778ef71670564e12faf9f8a98b7b61eaf02c0d855add36969deacfc4")
		sigPub2.Pubkey, _ = hex.DecodeString("0338db5069514e65bb4bf8c52d5b94d9f70ebdff659965d610e716c93fd3258c3a")

		fmt.Println("第二条hash签名结果")
		fmt.Println(hex.EncodeToString(sigPub2.Signature))
		fmt.Println("对应公钥")
		fmt.Println(hex.EncodeToString(sigPub2.Pubkey))
	}

	// 服务器收到签名结果后，使用签名结果填充TxHash结构体
	transHash[0].Normal.SigPub = *sigPub1
	transHash[1].Normal.SigPub = *sigPub2

	//回填后，将签名插入空交易单
	signedTrans, err := InsertSignatureIntoEmptyTransaction(emptyTrans, transHash, []TxUnlock{unlockData1, unlockData2})
	if err != nil {
		t.Error("插入交易单失败")
	} else {
		fmt.Println("合并之后的交易单")
		fmt.Println(signedTrans)
	}

	// 验证交易单
	pass := VerifyRawTransaction(signedTrans, []TxUnlock{unlockData1, unlockData2}, BTCMainnetAddressPrefix)
	if pass {
		fmt.Println("验证通过!")
	} else {
		t.Error("验证失败!")
	}
}
