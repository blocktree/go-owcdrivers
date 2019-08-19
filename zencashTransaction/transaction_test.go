package zencashTransaction

import (
	"encoding/hex"
	"fmt"
	"testing"
)

//案例一：
//输入为单个 P2PKH
func Test_case1(t *testing.T) {
	// 前置交易ID和UTXO对应的索引
	in := Vin{"c017610af048a33419a7232d3141a6a65888d7ab370c57b2641dda435f464486", uint32(2)}
	// 目标地址和发送金额
	out1 := Vout{"znWMqaB5mnPjpQciFdKBSuG8sSB89mmXSfA", uint64(10522258)}
	out2 := Vout{"znaigHgMAATBp2GsrRkK6wTTNZVE8eHsZGH", uint64(8048028)}
	out3 := Vout{"znWFC2wa6w5HwuGwabe5noHeRorNnFYMCVe", uint64(1203545)}
	out4 := Vout{"zna28uDbgGdhiasAYQTm6MkEqAZjGrjVRVJ", uint64(898885824)}

	blockHash := "000000000caa2184d928706c69c9e248e31f786ad750294533daa9c3bce1be10"
	blockHeight := uint64(560539)
	//锁定时间
	lockTime := uint32(0)

	//追加手续费支持
	replaceable := false

	///////构建空交易单
	emptyTrans, err := CreateEmptyRawTransaction([]Vin{in}, []Vout{out1, out2, out3, out4}, lockTime, replaceable, ZENMainnetAddressPrefix, blockHash, blockHeight)

	if err != nil {
		t.Error("构建空交易单失败")
	} else {
		fmt.Println("空交易单：")
		fmt.Println(emptyTrans)
	}

	//获取in的锁定脚本和amount
	//获取地址用于区分签名哈希
	// 填充TxUnlock结构体
	inLock := "76a91462023ebfb02d2e5528aed833ccf8fedf4be3b54488ac207b097f237915d06e02bdba3146f1fa2a525163f060a467422ef9460b0000000003968d08b4"

	//指向此类型地址的UTXO，获取签名哈希需要锁定脚本,赎回脚本应设置为 ""
	unlockData := TxUnlock{inLock, "", 0, SigHashAll}

	segwit := false

	/////////计算待签名交易单哈希
	transHash, err := CreateRawTransactionHashForSig(emptyTrans, []TxUnlock{unlockData}, segwit, ZENMainnetAddressPrefix)
	if err != nil {
		t.Error("创建待签交易单哈希失败")
	} else {
		for i, t := range transHash {
			fmt.Println("第", i+1, "个交易单哈希值为")
			fmt.Println(t)
		}
	}

	//////////////////////------//////////////////////
	//判断是否是多重签名
	if transHash[0].IsMultisig() {
		//获取地址
		//address := transHash[0].GetMultiTxPubkeys() //返回hex数组
	} else {
		//获取地址
		//address := transHash[0].GetNormalTxAddress() //返回hex串
	}
	//获取hash值
	hash := transHash[0].GetTxHashHex()
	// 通过地址和hash值来确定发送给哪个客户端进行签名
	//////////////////////------//////////////////////

	// 结果hash发送给客户端，客户端根据对应的地址可以找到私钥进行签名
	inPrikey := []byte{0x80, 0xbc, 0x39, 0x8d, 0x7c, 0x4a, 0x67, 0x4d, 0xaa, 0x97, 0x75, 0x66, 0xc2, 0xe6, 0xcd, 0x50, 0x40, 0x52, 0x00, 0x27, 0xe5, 0x7f, 0xe8, 0x06, 0xdf, 0xaa, 0x86, 0x8d, 0xf4, 0xcc, 0x43, 0xab}

	//签名
	sigPub, err := SignRawTransactionHash(hash, inPrikey)
	if err != nil {
		t.Error("hash签名失败")
	} else {
		sigPub.Signature, _ = hex.DecodeString("2c9a018f57f4990d5d2f00be0eebd0c986b54aeaa0acbab1539c320cad595f6b339118d37cd7562078152fec5a0fcf67cda84eef87dd844748f50efb94b0c32c")
		sigPub.Pubkey, _ = hex.DecodeString("034bbcf04216a64c3c776c9895da45af648024adddc1ef0a23125067e7f0094cc1")
		fmt.Println("hash签名结果为")
		fmt.Println(hex.EncodeToString(sigPub.Signature))
		fmt.Println("对应的公钥为")
		fmt.Println(hex.EncodeToString(sigPub.Pubkey))
	}

	// 签名结果返回给服务器
	// 拼接
	// 服务器收到签名结果后，回填TxHash结构体
	transHash[0].Normal.SigPub = *sigPub

	//交易单合并
	signedTrans, err := InsertSignatureIntoEmptyTransaction(emptyTrans, transHash, []TxUnlock{unlockData}, segwit)
	if err != nil {
		t.Error("插入交易单失败")
	} else {
		fmt.Println("合并之后的交易单")
		fmt.Println(signedTrans)
	}

	// 验证交易单
	pass := VerifyRawTransaction(signedTrans, []TxUnlock{unlockData}, segwit, ZENMainnetAddressPrefix)
	if pass {
		fmt.Println("验证通过!")
	} else {
		t.Error("验证失败!")
	}
}

func Test_case2(t *testing.T) {
	// 前置交易ID和UTXO对应的索引
	in := Vin{"cf2bfe6b3bb9c2902385bfe4d502315be78087f544cd605c1ea656a5f7f04703", uint32(1)}
	// 目标地址和发送金额
	out1 := Vout{"znX5wYUndj1i262mut8Xt5FknJJuCso8iY5", uint64(100000)}
	out2 := Vout{"znowCwfo4iz7mfndyqH4F2JLbWy19fESBsd", uint64(99230000)}

	blockHash := "00000001cf4e27ce1dd8028408ed0a48edd445ba388170c9468ba0d42fff3052"
	blockHeight := uint64(142091)
	//锁定时间
	lockTime := uint32(0)

	//追加手续费支持
	replaceable := false

	///////构建空交易单
	emptyTrans, err := CreateEmptyRawTransaction([]Vin{in}, []Vout{out1, out2}, lockTime, replaceable, ZENMainnetAddressPrefix, blockHash, blockHeight)

	if err != nil {
		t.Error("构建空交易单失败")
	} else {
		fmt.Println("空交易单：")
		fmt.Println(emptyTrans)
	}

	//获取in的锁定脚本和amount
	//获取地址用于区分签名哈希
	// 填充TxUnlock结构体
	inLock := "76a914faa54cf3b138bd587a7a12b1b2ca76d600a37ae388ac205230ff2fd4a08b46c9708138ba45d4ed480aed088402d81dce274ecf01000000030b2b02b4"

	//指向此类型地址的UTXO，获取签名哈希需要锁定脚本,赎回脚本应设置为 ""
	unlockData := TxUnlock{inLock, "", 0, SigHashAll}

	segwit := false

	/////////计算待签名交易单哈希
	transHash, err := CreateRawTransactionHashForSig(emptyTrans, []TxUnlock{unlockData}, segwit, ZENMainnetAddressPrefix)
	if err != nil {
		t.Error("创建待签交易单哈希失败")
	} else {
		for i, t := range transHash {
			fmt.Println("第", i+1, "个交易单哈希值为")
			fmt.Println(t)
		}
	}

	//////////////////////------//////////////////////
	//判断是否是多重签名
	if transHash[0].IsMultisig() {
		//获取地址
		//address := transHash[0].GetMultiTxPubkeys() //返回hex数组
	} else {
		//获取地址
		//address := transHash[0].GetNormalTxAddress() //返回hex串
	}
	//获取hash值
	hash := transHash[0].GetTxHashHex()
	fmt.Println("hash   :   ", hash)
	// 通过地址和hash值来确定发送给哪个客户端进行签名
	//////////////////////------//////////////////////

	// 结果hash发送给客户端，客户端根据对应的地址可以找到私钥进行签名
	inPrikey := []byte{0x80, 0xbc, 0x39, 0x8d, 0x7c, 0x4a, 0x67, 0x4d, 0xaa, 0x97, 0x75, 0x66, 0xc2, 0xe6, 0xcd, 0x50, 0x40, 0x52, 0x00, 0x27, 0xe5, 0x7f, 0xe8, 0x06, 0xdf, 0xaa, 0x86, 0x8d, 0xf4, 0xcc, 0x43, 0xab}

	//签名
	sigPub, err := SignRawTransactionHash(hash, inPrikey)
	if err != nil {
		t.Error("hash签名失败")
	} else {
		sigPub.Signature, _ = hex.DecodeString("f10bb88483b14486c5f795ed594e0ff5e67f09aafa13732caf2750c6641d97e6001cc5735af9e2765fd24457b2b05436774aee32a058f1883eef537fddd2dc74")
		sigPub.Pubkey, _ = hex.DecodeString("022904895a6ffedc8cbacb7f5cbaec4ed867755b3cdbccf549374e9728f5d2808c")
		fmt.Println("hash签名结果为")
		fmt.Println(hex.EncodeToString(sigPub.Signature))
		fmt.Println("对应的公钥为")
		fmt.Println(hex.EncodeToString(sigPub.Pubkey))
	}

	// 签名结果返回给服务器
	// 拼接
	// 服务器收到签名结果后，回填TxHash结构体
	transHash[0].Normal.SigPub = *sigPub

	//交易单合并
	signedTrans, err := InsertSignatureIntoEmptyTransaction(emptyTrans, transHash, []TxUnlock{unlockData}, segwit)
	if err != nil {
		t.Error("插入交易单失败")
	} else {
		fmt.Println("合并之后的交易单")
		fmt.Println(signedTrans)
	}

	// 验证交易单
	pass := VerifyRawTransaction(signedTrans, []TxUnlock{unlockData}, segwit, ZENMainnetAddressPrefix)
	if pass {
		fmt.Println("验证通过!")
	} else {
		t.Error("验证失败!")
	}
}

func Test_case3(t *testing.T) {
	// 前置交易ID和UTXO对应的索引
	in := Vin{"c017610af048a33419a7232d3141a6a65888d7ab370c57b2641dda435f464486", uint32(2)}
	// 目标地址和发送金额
	out1 := Vout{"zss5qxiTixuyZHBCgEdD91mLVUdjSwbDhqZ", uint64(10522258)}

	blockHash := "000000000caa2184d928706c69c9e248e31f786ad750294533daa9c3bce1be10"
	blockHeight := uint64(560539)
	//锁定时间
	lockTime := uint32(0)

	//追加手续费支持
	replaceable := false

	///////构建空交易单
	emptyTrans, err := CreateEmptyRawTransaction([]Vin{in}, []Vout{out1}, lockTime, replaceable, ZENMainnetAddressPrefix, blockHash, blockHeight)

	if err != nil {
		t.Error("构建空交易单失败")
	} else {
		fmt.Println("空交易单：")
		fmt.Println(emptyTrans)
	}

	//获取in的锁定脚本和amount
	//获取地址用于区分签名哈希
	// 填充TxUnlock结构体
	inLock := "76a91462023ebfb02d2e5528aed833ccf8fedf4be3b54488ac207b097f237915d06e02bdba3146f1fa2a525163f060a467422ef9460b0000000003968d08b4"

	//指向此类型地址的UTXO，获取签名哈希需要锁定脚本,赎回脚本应设置为 ""
	unlockData := TxUnlock{inLock, "", 0, SigHashAll}

	segwit := false

	/////////计算待签名交易单哈希
	transHash, err := CreateRawTransactionHashForSig(emptyTrans, []TxUnlock{unlockData}, segwit, ZENMainnetAddressPrefix)
	if err != nil {
		t.Error("创建待签交易单哈希失败")
	} else {
		for i, t := range transHash {
			fmt.Println("第", i+1, "个交易单哈希值为")
			fmt.Println(t)
		}
	}

	//////////////////////------//////////////////////
	//判断是否是多重签名
	if transHash[0].IsMultisig() {
		//获取地址
		//address := transHash[0].GetMultiTxPubkeys() //返回hex数组
	} else {
		//获取地址
		//address := transHash[0].GetNormalTxAddress() //返回hex串
	}
	//获取hash值
	hash := transHash[0].GetTxHashHex()
	// 通过地址和hash值来确定发送给哪个客户端进行签名
	//////////////////////------//////////////////////

	// 结果hash发送给客户端，客户端根据对应的地址可以找到私钥进行签名
	inPrikey := []byte{0x80, 0xbc, 0x39, 0x8d, 0x7c, 0x4a, 0x67, 0x4d, 0xaa, 0x97, 0x75, 0x66, 0xc2, 0xe6, 0xcd, 0x50, 0x40, 0x52, 0x00, 0x27, 0xe5, 0x7f, 0xe8, 0x06, 0xdf, 0xaa, 0x86, 0x8d, 0xf4, 0xcc, 0x43, 0xab}

	//签名
	sigPub, err := SignRawTransactionHash(hash, inPrikey)
	if err != nil {
		t.Error("hash签名失败")
	} else {
		//sigPub.Signature, _ = hex.DecodeString("2c9a018f57f4990d5d2f00be0eebd0c986b54aeaa0acbab1539c320cad595f6b339118d37cd7562078152fec5a0fcf67cda84eef87dd844748f50efb94b0c32c")
		//sigPub.Pubkey, _ = hex.DecodeString("034bbcf04216a64c3c776c9895da45af648024adddc1ef0a23125067e7f0094cc1")
		fmt.Println("hash签名结果为")
		fmt.Println(hex.EncodeToString(sigPub.Signature))
		fmt.Println("对应的公钥为")
		fmt.Println(hex.EncodeToString(sigPub.Pubkey))
	}

	// 签名结果返回给服务器
	// 拼接
	// 服务器收到签名结果后，回填TxHash结构体
	transHash[0].Normal.SigPub = *sigPub

	//交易单合并
	signedTrans, err := InsertSignatureIntoEmptyTransaction(emptyTrans, transHash, []TxUnlock{unlockData}, segwit)
	if err != nil {
		t.Error("插入交易单失败")
	} else {
		fmt.Println("合并之后的交易单")
		fmt.Println(signedTrans)
	}

	// 验证交易单
	pass := VerifyRawTransaction(signedTrans, []TxUnlock{unlockData}, segwit, ZENMainnetAddressPrefix)
	if pass {
		fmt.Println("验证通过!")
	} else {
		t.Error("验证失败!")
	}
}
