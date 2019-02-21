package btcTransaction

import (
	"encoding/hex"
	"fmt"
	"testing"
)

//案例一：
//输入为单个 P2PKH
func Test_case1(t *testing.T) {
	// 前置交易ID和UTXO对应的索引
	in := Vin{"5a02061670d3fa5cdc63854f75c607db6ddc7818ceb637015e1bf8f22649a55b", uint32(0)}
	// 目标地址和发送金额
	out := Vout{"mwmXzRM19gg5AB5Vu16dvfuhWujTq5PzvK", uint64(900000)}

	//锁定时间
	lockTime := uint32(0)

	//追加手续费支持
	replaceable := false

	///////构建空交易单
	emptyTrans, err := CreateEmptyRawTransaction([]Vin{in}, []Vout{out}, lockTime, replaceable, "btc", true)

	if err != nil {
		t.Error("构建空交易单失败")
	} else {
		fmt.Println("空交易单：")
		fmt.Println(emptyTrans)
	}

	//获取in的锁定脚本和amount
	//获取地址用于区分签名哈希
	// 填充TxUnlock结构体
	inLock := "76a914d46043209073ad39879356295562d952cd9dae3a88ac"

	//指向此类型地址的UTXO，获取签名哈希需要锁定脚本,赎回脚本应设置为 ""
	unlockData := TxUnlock{inLock, "", 0, SigHashAll}

	segwit := false

	/////////计算待签名交易单哈希
	transHash, err := CreateRawTransactionHashForSig(emptyTrans, []TxUnlock{unlockData}, segwit, "btc", true)
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
	pass := VerifyRawTransaction(signedTrans, []TxUnlock{unlockData}, segwit, "btc", true)
	if pass {
		fmt.Println("验证通过!")
	} else {
		t.Error("验证失败!")
	}
}

//案例二：
//输入为多个 P2PKH
func Test_case2(t *testing.T) {
	// 第一个输入 0.01428580
	in1 := Vin{"6cb0425bb4bb962db8359b8d3cbaa66ed8121091db6cfc9253f5bf1e9cef604f", uint32(0)}
	// 第二个输入 0.01284902
	in2 := Vin{"24cf52fb9588acf6a8413cd914532e27b5b376a6ebdbc98150cda76e1ae92b67", uint32(0)}

	// 目标地址与数额
	// 向 mwmXzRM19gg5AB5Vu16dvfuhWujTq5PzvK 发送 0.02
	// out 单位为聪
	out := Vout{"mwmXzRM19gg5AB5Vu16dvfuhWujTq5PzvK", uint64(2000000)}

	//锁定时间
	lockTime := uint32(0)

	//追加手续费支持
	replaceable := false

	/////////构建空交易单
	emptyTrans, err := CreateEmptyRawTransaction([]Vin{in1, in2}, []Vout{out}, lockTime, replaceable, "btc", true)

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

	segwit := false

	////////构建用于签名的交易单哈希
	transHash, err := CreateRawTransactionHashForSig(emptyTrans, []TxUnlock{unlockData1, unlockData2}, segwit, "btc", true)
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
	signedTrans, err := InsertSignatureIntoEmptyTransaction(emptyTrans, transHash, []TxUnlock{unlockData1, unlockData2}, segwit)
	if err != nil {
		t.Error("插入交易单失败")
	} else {
		fmt.Println("合并之后的交易单")
		fmt.Println(signedTrans)
	}

	// 验证交易单
	pass := VerifyRawTransaction(signedTrans, []TxUnlock{unlockData1, unlockData2}, segwit, "btc", true)
	if pass {
		fmt.Println("验证通过!")
	} else {
		t.Error("验证失败!")
	}
}

//案例三：
//输入为单个 P2WPKH
func Test_case3(t *testing.T) {

	// 前置交易ID和UTXO对应的索引
	in := Vin{"29b9a8f8a23f63f7604efc4c6aa1d6ae2e561ccc56131a81d167ccc3d5948884", uint32(0)}
	// 目标地址和发送金额
	out := Vout{"mwmXzRM19gg5AB5Vu16dvfuhWujTq5PzvK", uint64(3654707)}

	//锁定时间
	lockTime := uint32(0)

	//追加手续费支持
	replaceable := false

	///////构建空交易单
	emptyTrans, err := CreateEmptyRawTransaction([]Vin{in}, []Vout{out}, lockTime, replaceable, "btc", true)

	if err != nil {
		t.Error("构建空交易单失败")
	} else {
		fmt.Println("空交易单：")
		fmt.Println(emptyTrans)
	}

	//获取in的锁定脚本和amount
	//获取地址用于区分签名哈希
	// 填充TxUnlock结构体
	inLock := "a914671859ee6ae41decb6c855c53a60a8fa157b740a87"
	inRedeem := "00146c3fae076c083f83cc158fb1c886b6ae247201b6"
	amount := uint64(3754707)

	//指向此类型地址的UTXO，获取签名哈希需要锁定脚本,赎回脚本和amount
	unlockData := TxUnlock{inLock, inRedeem, amount, SigHashAll}

	segwit := true
	/////////计算待签名交易单哈希
	transHash, err := CreateRawTransactionHashForSig(emptyTrans, []TxUnlock{unlockData}, segwit, "btc", true)
	if err != nil {
		t.Error("创建待签交易单哈希失败")
	} else {
		for i, t := range transHash {
			fmt.Println("第", i+1, "个交易单哈希值为")
			fmt.Println(t)
		}
	}

	// 结果hash发送给客户端，客户端根据对应的地址可以找到私钥进行签名
	inPrikey := []byte{0x89, 0xde, 0x39, 0x3e, 0x2f, 0x37, 0x2d, 0xbd, 0x1a, 0xca, 0x72, 0x72, 0x68, 0x55, 0x14, 0xeb, 0xaa, 0x5a, 0x99, 0xc1, 0xe2, 0xb1, 0x89, 0xb3, 0xb9, 0xf3, 0x8f, 0x6c, 0x80, 0x32, 0xfe, 0x1d}

	//签名
	sigPub, err := SignRawTransactionHash(transHash[0].Hash, inPrikey)
	if err != nil {
		t.Error("hash签名失败")
	} else {
		fmt.Println("hash签名结果为")
		fmt.Println(hex.EncodeToString(sigPub.Signature))
		fmt.Println("对应的公钥为")
		fmt.Println(hex.EncodeToString(sigPub.Pubkey))
	}

	// 签名结果返回给服务器
	//拼接
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
	pass := VerifyRawTransaction(signedTrans, []TxUnlock{unlockData}, segwit, "btc", true)
	if pass {
		fmt.Println("验证通过!")
	} else {
		t.Error("验证失败!")
	}
}

//案例四：
//输入为多个 P2WPKH
func Test_case4(t *testing.T) {

	// 第一个输入
	in1 := Vin{"4318537801136991019cddcee9db07dc7ee1d6cb3960de543eb02fd04cc51d6d", uint32(1)}
	// 第二个输入
	in2 := Vin{"56c16b0875e65012041977750db7832b333a6b7c78e1fd68d817e88b4f798b8d", uint32(1)}

	// 目标地址与数额
	// 向 mwmXzRM19gg5AB5Vu16dvfuhWujTq5PzvK 发送 0.02
	// out 单位为聪
	out := Vout{"mwmXzRM19gg5AB5Vu16dvfuhWujTq5PzvK", uint64(22000000)}

	//锁定时间
	lockTime := uint32(0)

	//追加手续费支持
	replaceable := false

	///////构建空交易单
	emptyTrans, err := CreateEmptyRawTransaction([]Vin{in1, in2}, []Vout{out}, lockTime, replaceable, "btc", true)

	if err != nil {
		t.Error("构建空交易单失败")
	} else {
		fmt.Println("空交易单：")
		fmt.Println(emptyTrans)
	}

	// 获取in1 和 in2 的锁定脚本
	// 获取in1 和 in2 的赎回脚本
	// 获取in1 和 in2 的数额amount
	// 填充TxUnlock结构体
	in1Lock := "a91421f5946fcec43caa5d905d6e7c4d34aad57e20b387"
	in2Lock := "a914cfed6d5ae483deda33e92eb4c96fc1a281fbe06487"
	in1Redeem := "0014a972da7198dadfa4fb8886091d523a64a9e95a88"
	in2Redeem := "001469b6968a3d6917d0e1270b0b21d3605b86f3dee5"
	in1Amount := uint64(17411199)
	in2Amount := uint64(5559614)

	//针对此类指向脚本哈希地址的UTXO，此需要锁定脚本、赎回脚本以及该UTXO包含的数额方可计算待签交易单
	unlockData1 := TxUnlock{in1Lock, in1Redeem, in1Amount, SigHashAll}
	unlockData2 := TxUnlock{in2Lock, in2Redeem, in2Amount, SigHashAll}

	segwit := true
	/////////计算待签名交易单哈希
	transHash, err := CreateRawTransactionHashForSig(emptyTrans, []TxUnlock{unlockData1, unlockData2}, segwit, "btc", true)
	if err != nil {
		t.Error("创建待签交易单哈希失败")
	} else {
		for i, t := range transHash {
			fmt.Println("第", i+1, "个交易单哈希值为")
			fmt.Println(t)
		}
	}

	//将交易单哈希与每条哈希对应的地址发送给客户端
	//客户端根据对应地址派生私钥对哈希进行签名

	// 获取私钥
	// in1 address 2MvLnUoMyYmfxCqSbh7tpGpTxj18UPCvRqb
	//5ae604201f2e7dc1004603dd231a8c922b92abe836fe48eddaafe9320fa0cc60
	in1Prikey := []byte{0x5a, 0xe6, 0x04, 0x20, 0x1f, 0x2e, 0x7d, 0xc1, 0x00, 0x46, 0x03, 0xdd, 0x23, 0x1a, 0x8c, 0x92, 0x2b, 0x92, 0xab, 0xe8, 0x36, 0xfe, 0x48, 0xed, 0xda, 0xaf, 0xe9, 0x32, 0x0f, 0xa0, 0xcc, 0x60}
	// in2 address 2NCCeHip41kqwNJwopWmwqxrgM3VJiGDCsx   d25cf4f6744013b7421966de5e27e1fdc82f465fc863a751441dd74e5ace02bc
	in2Prikey := []byte{0xd2, 0x5c, 0xf4, 0xf6, 0x74, 0x40, 0x13, 0xb7, 0x42, 0x19, 0x66, 0xde, 0x5e, 0x27, 0xe1, 0xfd, 0xc8, 0x2f, 0x46, 0x5f, 0xc8, 0x63, 0xa7, 0x51, 0x44, 0x1d, 0xd7, 0x4e, 0x5a, 0xce, 0x02, 0xbc}

	// 客户端使用对应私钥进行签名

	//第一个
	sigPub1, err := SignRawTransactionHash(transHash[0].Hash, in1Prikey)
	if err != nil {
		t.Error("第一个hash签名失败")
	} else {
		fmt.Println("第一个hash的签名结果")
		fmt.Println(hex.EncodeToString(sigPub1.Signature))
		fmt.Println("对应的公钥为")
		fmt.Println(hex.EncodeToString(sigPub1.Pubkey))
	}

	//第二个
	sigPub2, err := SignRawTransactionHash(transHash[1].Hash, in2Prikey)
	if err != nil {
		t.Error("第二个hash签名失败")
	} else {
		fmt.Println("第二个hash的签名结果")
		fmt.Println(hex.EncodeToString(sigPub2.Signature))
		fmt.Println("对应的公钥为")
		fmt.Println(hex.EncodeToString(sigPub2.Pubkey))
	}

	// 服务器收到签名结果后，回填TxHash结构体
	transHash[0].Normal.SigPub = *sigPub1
	transHash[1].Normal.SigPub = *sigPub2

	//交易单合并
	signedTrans, err := InsertSignatureIntoEmptyTransaction(emptyTrans, transHash, []TxUnlock{unlockData1, unlockData2}, segwit)
	if err != nil {
		t.Error("插入交易单失败")
	} else {
		fmt.Println("合并之后的交易单")
		fmt.Println(signedTrans)
	}

	// 验证交易单
	pass := VerifyRawTransaction(signedTrans, []TxUnlock{unlockData1, unlockData2}, segwit, "btc", true)
	if pass {
		fmt.Println("验证通过!")
	} else {
		t.Error("验证失败!")
	}
}

//案例五
//输入混合了 P2PKH 和 P2WPKH
func Test_case5(t *testing.T) {
	//输入一
	//指向公钥哈希地址的UTXO
	in1 := Vin{"302759ff352b436db5b9c1700d6a1e5f29c324a9e3d69190b65b3553e05c9308", uint32(0)}
	//输入二
	//指向脚本哈希地址的UTXO
	in2 := Vin{"184d6c95f2d4c394f7ff63ce3388a65e8daa182351f64bd69abd64ac9fc51a23", uint32(1)}

	//输出
	// 向 mwmXzRM19gg5AB5Vu16dvfuhWujTq5PzvK 发送 0.673
	// out 单位为聪
	out := Vout{"mwmXzRM19gg5AB5Vu16dvfuhWujTq5PzvK", uint64(67300000)}

	//锁定时间
	lockTime := uint32(0)

	//追加手续费支持
	replaceable := false

	///////构建空交易单
	emptyTrans, err := CreateEmptyRawTransaction([]Vin{in1, in2}, []Vout{out}, lockTime, replaceable, "btc", true)

	if err != nil {
		t.Error("构建空交易单失败")
	} else {
		fmt.Println("空交易单：")
		fmt.Println(emptyTrans)
	}

	// 获取in1 和 in2 的锁定脚本
	// 获取in2 的赎回脚本
	// 获取in1 和 in2 的数额amount
	// 填充TxUnlock结构体
	in1Lock := "76a914d46043209073ad39879356295562d952cd9dae3a88ac"
	in2Lock := "a914bd52d5e36ab0cbd34d981843d1b620705a67927d87"
	in1Redeem := ""
	in2Redeem := "0014774334d4657dc2d251eff89af58d0a92bde2ec05"
	in1Amount := uint64(0)
	in2Amount := uint64(823237)

	//针对此类指向脚本哈希地址的UTXO，此需要锁定脚本、赎回脚本以及该UTXO包含的数额方可计算待签交易单
	unlockData1 := TxUnlock{in1Lock, in1Redeem, in1Amount, SigHashAll}
	unlockData2 := TxUnlock{in2Lock, in2Redeem, in2Amount, SigHashAll}

	segwit := true
	/////////计算待签名交易单哈希
	transHash, err := CreateRawTransactionHashForSig(emptyTrans, []TxUnlock{unlockData1, unlockData2}, segwit, "btc", true)
	if err != nil {
		t.Error("创建待签交易单哈希失败")
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
	//80bc398d7c4a674daa977566c2e6cd5040520027e57fe806dfaa868df4cc43ab
	in1Prikey := []byte{0x80, 0xbc, 0x39, 0x8d, 0x7c, 0x4a, 0x67, 0x4d, 0xaa, 0x97, 0x75, 0x66, 0xc2, 0xe6, 0xcd, 0x50, 0x40, 0x52, 0x00, 0x27, 0xe5, 0x7f, 0xe8, 0x06, 0xdf, 0xaa, 0x86, 0x8d, 0xf4, 0xcc, 0x43, 0xab}
	// in2 address 2NAWGw3wHZTnHnXRT1GZF2eB6a6DUqqHCu8
	// 7e41219c19076595dc17421ffd894188354d151539c1be1c15e975fcc9c47789
	in2Prikey := []byte{0x7e, 0x41, 0x21, 0x9c, 0x19, 0x07, 0x65, 0x95, 0xdc, 0x17, 0x42, 0x1f, 0xfd, 0x89, 0x41, 0x88, 0x35, 0x4d, 0x15, 0x15, 0x39, 0xc1, 0xbe, 0x1c, 0x15, 0xe9, 0x75, 0xfc, 0xc9, 0xc4, 0x77, 0x89}

	//第一个
	sigPub1, err := SignRawTransactionHash(transHash[0].Hash, in1Prikey)
	if err != nil {
		t.Error("第一个hash签名失败")
	} else {
		fmt.Println("第一个hash签名结果为")
		fmt.Println(hex.EncodeToString(sigPub1.Signature))
		fmt.Println("对应的公钥为")
		fmt.Println(hex.EncodeToString(sigPub1.Pubkey))
	}
	//第二个
	sigPub2, err := SignRawTransactionHash(transHash[1].Hash, in2Prikey)
	if err != nil {
		t.Error("第二个hash签名失败")
	} else {
		fmt.Println("第二个hash签名结果为")
		fmt.Println(hex.EncodeToString(sigPub2.Signature))
		fmt.Println("对应的公钥为")
		fmt.Println(hex.EncodeToString(sigPub2.Pubkey))
	}

	// 服务器收到签名结果后，回填TxHash结构体
	transHash[0].Normal.SigPub = *sigPub1
	transHash[1].Normal.SigPub = *sigPub2

	//交易单合并
	signedTrans, err := InsertSignatureIntoEmptyTransaction(emptyTrans, transHash, []TxUnlock{unlockData1, unlockData2}, segwit)
	if err != nil {
		t.Error("插入交易单失败")
	} else {
		fmt.Println("合并之后的交易单")
		fmt.Println(signedTrans)
	}

	// 验证交易单
	pass := VerifyRawTransaction(signedTrans, []TxUnlock{unlockData1, unlockData2}, segwit, "btc", true)
	if pass {
		fmt.Println("验证通过!")
	} else {
		t.Error("验证失败!")
	}

}

// 案例六
// 输入为Bech32新型地址
func Test_case6(t *testing.T) {
	//一个输入
	//指向bech32地址类型的UTXO
	in := Vin{"b6911cfc26cc7a354439af5997ebf05bad96544a0f93ff3b3724267b048a2810", uint32(0)}

	//一个输出
	//向P2PKH类型地址转0.0098个比特币
	out := Vout{"mvH6BJvP4SyX99tCoBEpWGTkvAq5E7hKp9", uint64(980000)}

	//锁定时间
	lockTime := uint32(0)

	//追加手续费支持
	replaceable := false

	///////构建空交易单
	emptyTrans, err := CreateEmptyRawTransaction([]Vin{in}, []Vout{out}, lockTime, replaceable, "btc", true)

	if err != nil {
		t.Error("构建空交易单失败")
	} else {
		fmt.Println("空交易单：")
		fmt.Println(emptyTrans)
	}

	//获取in的锁定脚本和amount
	//获取地址用于区分签名哈希
	// 填充TxUnlock结构体
	inLock := "0014d46043209073ad39879356295562d952cd9dae3a"
	inRedeem := ""
	inAmount := uint64(1000000)

	//指向此类型地址的UTXO，获取签名哈希需要锁定脚本，数额，赎回脚本应设置为 ""
	unlockData := TxUnlock{inLock, inRedeem, inAmount, SigHashAll}

	segwit := true
	/////////计算待签名交易单哈希
	transHash, err := CreateRawTransactionHashForSig(emptyTrans, []TxUnlock{unlockData}, segwit, "btc", true)
	if err != nil {
		t.Error("创建待签交易单哈希失败")
	} else {
		for i, t := range transHash {
			fmt.Println("第", i+1, "个交易单哈希值为")
			fmt.Println(t)
		}
	}

	//将交易单哈希与每条哈希对应的地址发送给客户端
	//客户端根据对应地址派生私钥对哈希进行签名

	inPrikey := []byte{0x80, 0xbc, 0x39, 0x8d, 0x7c, 0x4a, 0x67, 0x4d, 0xaa, 0x97, 0x75, 0x66, 0xc2, 0xe6, 0xcd, 0x50, 0x40, 0x52, 0x00, 0x27, 0xe5, 0x7f, 0xe8, 0x06, 0xdf, 0xaa, 0x86, 0x8d, 0xf4, 0xcc, 0x43, 0xab}

	sigPub, err := SignRawTransactionHash(transHash[0].Hash, inPrikey)
	if err != nil {
		t.Error("hash签名失败")
	} else {
		fmt.Println("hash签名结果为")
		fmt.Println(hex.EncodeToString(sigPub.Signature))
		fmt.Println("对应的公钥为")
		fmt.Println(hex.EncodeToString(sigPub.Pubkey))
	}

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
	pass := VerifyRawTransaction(signedTrans, []TxUnlock{unlockData}, segwit, "btc", true)
	if pass {
		fmt.Println("验证通过!")
	} else {
		t.Error("验证失败!")
	}
}

// 案例七
// 输入为Bech32新型地址
func Test_case7(t *testing.T) {
	// 前置交易ID和UTXO对应的索引
	in := Vin{"b6911cfc26cc7a354439af5997ebf05bad96544a0f93ff3b3724267b048a2810", uint32(1)}
	// 目标地址和发送金额
	out := Vout{"mwmXzRM19gg5AB5Vu16dvfuhWujTq5PzvK", uint64(61863300)}

	//锁定时间
	lockTime := uint32(0)

	//追加手续费支持
	replaceable := false

	///////构建空交易单
	emptyTrans, err := CreateEmptyRawTransaction([]Vin{in}, []Vout{out}, lockTime, replaceable, "btc", true)

	if err != nil {
		t.Error("构建空交易单失败")
	} else {
		fmt.Println("空交易单：")
		fmt.Println(emptyTrans)
	}

	//获取in的锁定脚本和amount
	//获取地址用于区分签名哈希
	// 填充TxUnlock结构体
	inLock := "0014a68b57eff4748fe5d0e69e4253af20296da334d8"
	inRedeem := ""
	amount := uint64(63863300)

	//指向此类型地址的UTXO，获取签名哈希需要锁定脚本,赎回脚本和amount
	unlockData := TxUnlock{inLock, inRedeem, amount, SigHashAll}

	segwit := true

	/////////计算待签名交易单哈希
	transHash, err := CreateRawTransactionHashForSig(emptyTrans, []TxUnlock{unlockData}, segwit, "btc", true)
	if err != nil {
		t.Error("创建待签交易单哈希失败")
	} else {
		for i, t := range transHash {
			fmt.Println("第", i+1, "个交易单哈希值为")
			fmt.Println(t)
		}
	}

	// 结果hash发送给客户端，客户端根据对应的地址可以找到私钥进行签名
	inPrikey := []byte{0x84, 0x98, 0x23, 0xd2, 0x2d, 0x81, 0xe4, 0x9e, 0xb7, 0x19, 0x06, 0x6b, 0xcf, 0x7e, 0xd1, 0x73, 0xe6, 0x09, 0x48, 0x22, 0xb0, 0xea, 0x4e, 0x79, 0x3f, 0x1d, 0x85, 0x97, 0xa5, 0x06, 0x0d, 0x27}

	//签名
	sigPub, err := SignRawTransactionHash(transHash[0].Hash, inPrikey)
	if err != nil {
		t.Error("hash签名失败")
	} else {
		fmt.Println("hash签名结果为")
		fmt.Println(hex.EncodeToString(sigPub.Signature))
		fmt.Println("对应的公钥为")
		fmt.Println(hex.EncodeToString(sigPub.Pubkey))
	}

	// 签名结果返回给服务器
	//拼接
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
	pass := VerifyRawTransaction(signedTrans, []TxUnlock{unlockData}, segwit, "btc", true)
	if pass {
		fmt.Println("验证通过!")
	} else {
		t.Error("验证失败!")
	}
}

//案例八
//多重签名流程 隔离认证开启
func Test_case8(t *testing.T) {
	// step1
	// 创建多重签名地址

	// 2 of  3
	required := byte(2)
	// 获取来自三方的公钥，可为压缩或不压缩格式
	pubA := []byte{0x02, 0x9F, 0xC3, 0x70, 0xE6, 0x31, 0x59, 0xC0, 0x2C, 0x8E, 0x4A, 0x40, 0xCA, 0xE2, 0xFF, 0xB7, 0xBE, 0xE0, 0x60, 0xF4, 0x5A, 0xA9, 0x5C, 0x2B, 0x92, 0xAC, 0x11, 0x93, 0xE4, 0x3A, 0x0B, 0xB4, 0x77}
	pubB := []byte{0x03, 0xBA, 0x48, 0x38, 0xA4, 0x2D, 0x20, 0xE3, 0xED, 0x56, 0x3F, 0xCC, 0x87, 0x69, 0xE3, 0x54, 0xE7, 0x7D, 0x88, 0x35, 0x10, 0x4C, 0x92, 0x75, 0x85, 0x20, 0x38, 0x09, 0xB9, 0xD3, 0xBD, 0x9E, 0xA5}
	pubC := []byte{0x02, 0xC2, 0xE8, 0x65, 0xFC, 0x60, 0x17, 0x1F, 0x7F, 0xCD, 0xFB, 0xE8, 0xC2, 0x9A, 0xE4, 0x54, 0x46, 0x02, 0x56, 0xF3, 0xBA, 0xAD, 0x25, 0x34, 0x28, 0xE8, 0xD4, 0x0A, 0x37, 0x85, 0x2B, 0x38, 0x4A}

	//填充成为2维数组，获取多重签名地址
	segwit := true
	address, redeem, err := CreateMultiSig(required, [][]byte{pubA, pubB, pubC}, segwit, "btc", true)
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

	//锁定时间
	lockTime := uint32(0)

	//追加手续费支持
	replaceable := false

	emptyTrans, err := CreateEmptyRawTransaction([]Vin{in}, []Vout{out}, lockTime, replaceable, "btc", true)
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
	transHash, err := CreateRawTransactionHashForSig(emptyTrans, []TxUnlock{unlockData}, segwit, "btc", true)
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
	signedTrans, err := InsertSignatureIntoEmptyTransaction(emptyTrans, transHash, []TxUnlock{unlockData}, segwit)
	if err != nil {
		t.Error("插入交易单失败")
	} else {
		fmt.Println("合并之后的交易单")
		fmt.Println(signedTrans)
	}

	// 验证交易单
	pass := VerifyRawTransaction(signedTrans, []TxUnlock{unlockData}, segwit, "btc", true)
	if pass {
		fmt.Println("验证通过!")
	} else {
		t.Error("验证失败!")
	}
}

//案例九
//多重签名流程 隔离认证开启
func Test_case9(t *testing.T) {

	// step1
	// 创建多重签名地址

	// 2 of  3
	required := byte(2)
	// 获取来自三方的公钥，可为压缩或不压缩格式
	pubA := []byte{0x02, 0x9F, 0xC3, 0x70, 0xE6, 0x31, 0x59, 0xC0, 0x2C, 0x8E, 0x4A, 0x40, 0xCA, 0xE2, 0xFF, 0xB7, 0xBE, 0xE0, 0x60, 0xF4, 0x5A, 0xA9, 0x5C, 0x2B, 0x92, 0xAC, 0x11, 0x93, 0xE4, 0x3A, 0x0B, 0xB4, 0x77}
	pubB := []byte{0x03, 0xBA, 0x48, 0x38, 0xA4, 0x2D, 0x20, 0xE3, 0xED, 0x56, 0x3F, 0xCC, 0x87, 0x69, 0xE3, 0x54, 0xE7, 0x7D, 0x88, 0x35, 0x10, 0x4C, 0x92, 0x75, 0x85, 0x20, 0x38, 0x09, 0xB9, 0xD3, 0xBD, 0x9E, 0xA5}
	pubC := []byte{0x02, 0xC2, 0xE8, 0x65, 0xFC, 0x60, 0x17, 0x1F, 0x7F, 0xCD, 0xFB, 0xE8, 0xC2, 0x9A, 0xE4, 0x54, 0x46, 0x02, 0x56, 0xF3, 0xBA, 0xAD, 0x25, 0x34, 0x28, 0xE8, 0xD4, 0x0A, 0x37, 0x85, 0x2B, 0x38, 0x4A}

	//填充成为2维数组，获取多重签名地址

	segwit := true
	address, redeem, err := CreateMultiSig(required, [][]byte{pubA, pubB, pubC}, segwit, "btc", true)
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
	in := Vin{"7a9e9158657b6040fc2f0c0fcf97d3f58468bb39d1fb5111a8a5e2707da68280", uint32(0)}
	out := Vout{"mwmXzRM19gg5AB5Vu16dvfuhWujTq5PzvK", uint64(9800000)}

	//锁定时间
	lockTime := uint32(0)

	//追加手续费支持
	replaceable := false

	emptyTrans, err := CreateEmptyRawTransaction([]Vin{in}, []Vout{out}, lockTime, replaceable, "btc", true)
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
	transHash, err := CreateRawTransactionHashForSig(emptyTrans, []TxUnlock{unlockData}, segwit, "btc", true)
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
	signedTrans, err := InsertSignatureIntoEmptyTransaction(emptyTrans, transHash, []TxUnlock{unlockData}, segwit)
	if err != nil {
		t.Error("插入交易单失败")
	} else {
		fmt.Println("合并之后的交易单")
		fmt.Println(signedTrans)
	}

	// 验证交易单
	pass := VerifyRawTransaction(signedTrans, []TxUnlock{unlockData}, segwit, "btc", true)
	if pass {
		fmt.Println("验证通过!")
	} else {
		t.Error("验证失败!")
	}
}

//案例十
//多重签名流程 无隔离认证
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
	segwit := false
	address, redeem, err := CreateMultiSig(required, [][]byte{pubA, pubB, pubC}, segwit, "btc", true)
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

	//锁定时间
	lockTime := uint32(0)

	//追加手续费支持
	replaceable := false

	emptyTrans, err := CreateEmptyRawTransaction([]Vin{in}, []Vout{out}, lockTime, replaceable, "btc", true)
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
	transHash, err := CreateRawTransactionHashForSig(emptyTrans, []TxUnlock{unlockData}, segwit, "btc", true)
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
	signedTrans, err := InsertSignatureIntoEmptyTransaction(emptyTrans, transHash, []TxUnlock{unlockData}, segwit)
	if err != nil {
		t.Error("插入交易单失败")
	} else {
		fmt.Println("合并之后的交易单")
		fmt.Println(signedTrans)
	}

	// 验证交易单
	pass := VerifyRawTransaction(signedTrans, []TxUnlock{unlockData}, segwit, "btc", true)
	if pass {
		fmt.Println("验证通过!")
	} else {
		t.Error("验证失败!")
	}
}

//案例十一
//多重签名流程 无隔离认证
func Test_case11(t *testing.T) {
	// step1
	// 创建多重签名地址

	// 2 of  3
	required := byte(2)
	// 获取来自三方的公钥，可为压缩或不压缩格式
	pubA := []byte{0x02, 0x9F, 0xC3, 0x70, 0xE6, 0x31, 0x59, 0xC0, 0x2C, 0x8E, 0x4A, 0x40, 0xCA, 0xE2, 0xFF, 0xB7, 0xBE, 0xE0, 0x60, 0xF4, 0x5A, 0xA9, 0x5C, 0x2B, 0x92, 0xAC, 0x11, 0x93, 0xE4, 0x3A, 0x0B, 0xB4, 0x77}
	pubB := []byte{0x03, 0xBA, 0x48, 0x38, 0xA4, 0x2D, 0x20, 0xE3, 0xED, 0x56, 0x3F, 0xCC, 0x87, 0x69, 0xE3, 0x54, 0xE7, 0x7D, 0x88, 0x35, 0x10, 0x4C, 0x92, 0x75, 0x85, 0x20, 0x38, 0x09, 0xB9, 0xD3, 0xBD, 0x9E, 0xA5}
	pubC := []byte{0x02, 0xC2, 0xE8, 0x65, 0xFC, 0x60, 0x17, 0x1F, 0x7F, 0xCD, 0xFB, 0xE8, 0xC2, 0x9A, 0xE4, 0x54, 0x46, 0x02, 0x56, 0xF3, 0xBA, 0xAD, 0x25, 0x34, 0x28, 0xE8, 0xD4, 0x0A, 0x37, 0x85, 0x2B, 0x38, 0x4A}

	//填充成为2维数组，获取多重签名地址
	segwit := false
	address, redeem, err := CreateMultiSig(required, [][]byte{pubA, pubB, pubC}, segwit, "btc", true)
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
	in := Vin{"b19a7af60c49b3a44495865588fc75e1abf7bbfbd18690a57d8fcbfc0437889a", uint32(0)}
	out := Vout{"mwmXzRM19gg5AB5Vu16dvfuhWujTq5PzvK", uint64(9800000)}

	//锁定时间
	lockTime := uint32(0)

	//追加手续费支持
	replaceable := false

	emptyTrans, err := CreateEmptyRawTransaction([]Vin{in}, []Vout{out}, lockTime, replaceable, "btc", true)
	if err != nil {
		t.Error("构建空交易单失败")
	} else {
		fmt.Println("空交易单：")
		fmt.Println(emptyTrans)
	}

	// 构建交易单签名哈希
	inLock := "a91406b3e7277e832049aa1bb88184f1bf39a94df5de87"
	inRedeem := redeem
	inAmount := uint64(10000000)

	unlockData := TxUnlock{inLock, inRedeem, inAmount, SigHashAll}

	/////////计算待签名交易单哈希
	transHash, err := CreateRawTransactionHashForSig(emptyTrans, []TxUnlock{unlockData}, segwit, "btc", true)
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
	signedTrans, err := InsertSignatureIntoEmptyTransaction(emptyTrans, transHash, []TxUnlock{unlockData}, segwit)
	if err != nil {
		t.Error("插入交易单失败")
	} else {
		fmt.Println("合并之后的交易单")
		fmt.Println(signedTrans)
	}

	// 验证交易单
	pass := VerifyRawTransaction(signedTrans, []TxUnlock{unlockData}, segwit, "btc", true)
	if pass {
		fmt.Println("验证通过!")
	} else {
		t.Error("验证失败!")
	}
}

func Test_tmp(t *testing.T) {
	// 前置交易ID和UTXO对应的索引
	in := Vin{"6b5be8fc6a2c17c11751b388c827ee106355d0742be52a23d33616d22ee90933", uint32(0)}
	// 目标地址和发送金额
	out1 := Vout{"mzK3BsJDMp6rviS5ZJuQfPxi6JjgV3m8Fu", uint64(30000)}
	out2 := Vout{"n4DLw2DoNE86qkL5aQKRbvuHeU5Urkz21T", uint64(267740)}

	//锁定时间
	lockTime := uint32(0)

	//追加手续费支持
	replaceable := false

	///////构建空交易单
	emptyTrans, err := CreateEmptyRawTransaction([]Vin{in}, []Vout{out1, out2}, lockTime, replaceable, "btc", true)

	if err != nil {
		t.Error("构建空交易单失败")
	} else {
		fmt.Println("空交易单：")
		fmt.Println(emptyTrans)
	}

	//获取in的锁定脚本和amount
	//获取地址用于区分签名哈希
	// 填充TxUnlock结构体
	inLock := "76a9148c0bceb59d452b3e077f73a420b8bfe09e0550a788ac"

	//指向此类型地址的UTXO，获取签名哈希需要锁定脚本,赎回脚本应设置为 ""
	unlockData := TxUnlock{inLock, "", 0, SigHashAll}

	/////////计算待签名交易单哈希
	transHash, err := CreateRawTransactionHashForSig(emptyTrans, []TxUnlock{unlockData}, false, "btc", true)
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
	inPrikey := []byte{0x45, 0x5d, 0x44, 0x9c, 0x29, 0x8e, 0xca, 0x9c, 0x69, 0xf7, 0xc1, 0xee, 0xb6, 0x6a, 0xfe, 0x40, 0x0f, 0x67, 0xe7, 0xe3, 0x13, 0x18, 0xc8, 0xd8, 0x10, 0x05, 0xc8, 0xc0, 0xc7, 0xab, 0xd8, 0xb5}

	//签名
	sigPub, err := SignRawTransactionHash(hash, inPrikey)
	if err != nil {
		t.Error("hash签名失败")
	} else {
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
	signedTrans, err := InsertSignatureIntoEmptyTransaction(emptyTrans, transHash, []TxUnlock{unlockData}, false)
	if err != nil {
		t.Error("插入交易单失败")
	} else {
		fmt.Println("合并之后的交易单")
		fmt.Println(signedTrans)
	}

	// 验证交易单
	pass := VerifyRawTransaction(signedTrans, []TxUnlock{unlockData}, false, "btc", true)
	if pass {
		fmt.Println("验证通过!")
	} else {
		t.Error("验证失败!")
	}
}
func Test_tmp2(t *testing.T) {
	// 第一个输入 0.01428580
	in1 := Vin{"c883af27e668563dedfe9b2927c891872765906222e3497b1d9c588743d0e7db", uint32(0)}
	// 第二个输入 0.01284902
	in2 := Vin{"c883af27e668563dedfe9b2927c891872765906222e3497b1d9c588743d0e7db", uint32(1)}

	// 目标地址与数额
	// 向 mwmXzRM19gg5AB5Vu16dvfuhWujTq5PzvK 发送 0.02
	// out 单位为聪
	out1 := Vout{"mzK3BsJDMp6rviS5ZJuQfPxi6JjgV3m8Fu", uint64(30000)}
	out2 := Vout{"n4DLw2DoNE86qkL5aQKRbvuHeU5Urkz21T", uint64(264000)}

	//锁定时间
	lockTime := uint32(0)

	//追加手续费支持
	replaceable := false

	/////////构建空交易单
	emptyTrans, err := CreateEmptyRawTransaction([]Vin{in1, in2}, []Vout{out1, out2}, lockTime, replaceable, "btc", true)

	if err != nil {
		t.Error("构建空交易单失败")
	} else {
		fmt.Println("空交易单：")
		fmt.Println(emptyTrans)
	}

	// 获取in1 和 in2 的锁定脚本
	// 填充TxUnlock结构体
	in1Lock := "76a914ce297bad01313bd91a4c65a9ac54e7f285042bfb88ac"
	in2Lock := "76a914f8f64d6d0962c6dc5876daaf091d81d20a8ae7c388ac"

	//针对此类指向公钥哈希地址的UTXO，此处仅需要锁定脚本即可计算待签交易单
	unlockData1 := TxUnlock{in1Lock, "", uint64(0), SigHashAll}
	unlockData2 := TxUnlock{in2Lock, "", uint64(0), SigHashAll}

	////////构建用于签名的交易单哈希
	transHash, err := CreateRawTransactionHashForSig(emptyTrans, []TxUnlock{unlockData1, unlockData2}, false, "btc", true)
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
	in1Prikey := []byte{0x4d, 0x1f, 0x94, 0x70, 0x69, 0x19, 0x27, 0x9e, 0xdc, 0x71, 0x07, 0xc2, 0x32, 0x9c, 0x70, 0x74, 0x8b, 0xe1, 0x0a, 0xc9, 0x18, 0x9a, 0xeb, 0x20, 0xc4, 0x98, 0x2d, 0x0d, 0x71, 0x40, 0x9a, 0x0b}
	// in2 address mzsts8xiVWv8uGEYUrAB6XzKXZPiX9j6jq
	in2Prikey := []byte{0xd7, 0x2e, 0x8d, 0x5b, 0xb4, 0x03, 0xeb, 0x9f, 0x4d, 0x64, 0x56, 0x4d, 0xf5, 0xf1, 0xbb, 0xa5, 0x53, 0xda, 0x68, 0x06, 0x89, 0x01, 0xd8, 0x37, 0x23, 0x20, 0xb4, 0xa1, 0x9c, 0xf7, 0xdc, 0xa0}

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
	signedTrans, err := InsertSignatureIntoEmptyTransaction(emptyTrans, transHash, []TxUnlock{unlockData1, unlockData2}, false)
	if err != nil {
		t.Error("插入交易单失败")
	} else {
		fmt.Println("合并之后的交易单")
		fmt.Println(signedTrans)
	}

	// 验证交易单
	pass := VerifyRawTransaction(signedTrans, []TxUnlock{unlockData1, unlockData2}, false, "btc", true)
	if pass {
		fmt.Println("验证通过!")
	} else {
		t.Error("验证失败!")
	}
}
