package bitcoincashTransaction

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func Test_83df2066934a29aa0df62dfc72ce6c625406f9b69331c4b33eb2fc7c7c337c71(t *testing.T) {

	in := Vin{"3b8a0b6150d72d1a2283ea9fe8f309255ae2584acd0d5579b625a82e020ad0b7", uint32(1)}

	out := Vout{"1MG4HABimSJh166Dhu7wmWTPaX6WqBDG7V", uint64(5394)}

	//锁定时间
	lockTime := uint32(0)

	//追加手续费支持
	replaceable := false

	addressPrefix := AddressPrefix{[]byte{0x00}, []byte{0x05}, nil, "bc"}


	///////构建空交易单
	emptyTrans, err := CreateEmptyRawTransaction([]Vin{in}, []Vout{out}, lockTime, replaceable, addressPrefix)

	if err != nil {
		t.Error("构建空交易单失败")
	} else {
		fmt.Println("空交易单：")
		fmt.Println(emptyTrans)
	}

	//获取in的锁定脚本和amount
	//获取地址用于区分签名哈希
	// 填充TxUnlock结构体
	inLock := "76a914b1333c4af967887b3fa270e4712caec73469f49a88ac"

	//指向此类型地址的UTXO，获取签名哈希需要锁定脚本,赎回脚本应设置为 ""
	unlockData := TxUnlock{inLock, "", 5586, SigHashAll}

	segwit := false

	/////////计算待签名交易单哈希
	transHash, err := CreateRawTransactionHashForSig(emptyTrans, []TxUnlock{unlockData}, segwit, addressPrefix)
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
		sigPub.Signature, _ = hex.DecodeString("d027922b3df11b84aefc23957a2e54269f74e3eb6bef65fb0d0c1ffc7f77266843d2e5aa64da1557aeb92d243ae7d1e0b181bf2986b12c2edc963f543ef2f426")
		fmt.Println("hash签名结果为")
		fmt.Println(hex.EncodeToString(sigPub.Signature))
		sigPub.Pubkey, _ = hex.DecodeString("02b9909c3dfcdd1c3153eb339f1c8b309bd6dcc2c5238859dbee1a71a3aeff1ee1")
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
	pass := VerifyRawTransaction(signedTrans, []TxUnlock{unlockData}, segwit, addressPrefix)
	if pass {
		fmt.Println("验证通过!")
	} else {
		t.Error("验证失败!")
	}
}

func Test_1f2359a23deb1225a97d1f1fade53d16dcb8f461bda52c1b37a1b48f3dd0ceac(t *testing.T) {

	in1 := Vin{"2823f1f42559b2b9aef7babb05d5056110872be793a1cf78fe5880b164af5bd7", uint32(0)}
	in2 := Vin{"5e3a01deb434976db3afd0ea1fa375fb27b8b9262638c738853061a94fff24cb", uint32(1)}

	out1 := Vout{"3BGWuzsJVGzNQ75zUqoqdxrXdjsVztNBGv", uint64(1400000)}
	out2 := Vout{"13DqwkqhWV5hvCv35JAxnFfvyeCT36MrVp", uint64(3282993)}

	//锁定时间
	lockTime := uint32(0)

	//追加手续费支持
	replaceable := false

	addressPrefix := AddressPrefix{[]byte{0x00}, []byte{0x05}, nil, "bc"}


	///////构建空交易单
	emptyTrans, err := CreateEmptyRawTransaction([]Vin{in1, in2}, []Vout{out1, out2}, lockTime, replaceable, addressPrefix)

	if err != nil {
		t.Error("构建空交易单失败")
	} else {
		fmt.Println("空交易单：")
		fmt.Println(emptyTrans)
	}

	//获取in的锁定脚本和amount
	//获取地址用于区分签名哈希
	// 填充TxUnlock结构体
	inLock1 := "76a9148f630b3f370991732d08d04878143e8cab6672f188ac"

	//指向此类型地址的UTXO，获取签名哈希需要锁定脚本,赎回脚本应设置为 ""
	unlockData1 := TxUnlock{inLock1, "", 699546, SigHashAll}

	inLock2 := "76a9141c3366ee38ba51d5856d337490ea5bb72ecef8c788ac"

	//指向此类型地址的UTXO，获取签名哈希需要锁定脚本,赎回脚本应设置为 ""
	unlockData2 := TxUnlock{inLock2, "", 3983824, SigHashAll}

	segwit := false

	/////////计算待签名交易单哈希
	transHash, err := CreateRawTransactionHashForSig(emptyTrans, []TxUnlock{unlockData1, unlockData2}, segwit, addressPrefix)
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
	hash1 := transHash[0].GetTxHashHex()
	// 通过地址和hash值来确定发送给哪个客户端进行签名
	//////////////////////------//////////////////////

	// 结果hash发送给客户端，客户端根据对应的地址可以找到私钥进行签名
	inPrikey1 := []byte{0x80, 0xbc, 0x39, 0x8d, 0x7c, 0x4a, 0x67, 0x4d, 0xaa, 0x97, 0x75, 0x66, 0xc2, 0xe6, 0xcd, 0x50, 0x40, 0x52, 0x00, 0x27, 0xe5, 0x7f, 0xe8, 0x06, 0xdf, 0xaa, 0x86, 0x8d, 0xf4, 0xcc, 0x43, 0xab}

	//签名
	sigPub1, err := SignRawTransactionHash(hash1, inPrikey1)
	if err != nil {
		t.Error("hash签名失败")
	} else {
		sigPub1.Signature, _ = hex.DecodeString("48d433e18a67adeab404f3f20d28afa98a32bb13eeb010130dccc50144dd69826d17c8fe8dc49e6b0283c271d8abea1871ea0bf9279558b539d62f6095ee7485")
		fmt.Println("hash签名结果为")
		fmt.Println(hex.EncodeToString(sigPub1.Signature))
		sigPub1.Pubkey, _ = hex.DecodeString("039c45ccdac3e34683302e6c82e194b2720fd2a49ded76ecd00381ca1024152959")
		fmt.Println("对应的公钥为")
		fmt.Println(hex.EncodeToString(sigPub1.Pubkey))
	}

	// 签名结果返回给服务器
	// 拼接
	// 服务器收到签名结果后，回填TxHash结构体
	transHash[0].Normal.SigPub = *sigPub1


	hash2 := transHash[0].GetTxHashHex()
	// 通过地址和hash值来确定发送给哪个客户端进行签名
	//////////////////////------//////////////////////

	// 结果hash发送给客户端，客户端根据对应的地址可以找到私钥进行签名
	inPrikey2 := []byte{0x80, 0xbc, 0x39, 0x8d, 0x7c, 0x4a, 0x67, 0x4d, 0xaa, 0x97, 0x75, 0x66, 0xc2, 0xe6, 0xcd, 0x50, 0x40, 0x52, 0x00, 0x27, 0xe5, 0x7f, 0xe8, 0x06, 0xdf, 0xaa, 0x86, 0x8d, 0xf4, 0xcc, 0x43, 0xab}

	//签名
	sigPub2, err := SignRawTransactionHash(hash2, inPrikey2)
	if err != nil {
		t.Error("hash签名失败")
	} else {
		sigPub2.Signature, _ = hex.DecodeString("7deadca8cb85df9961944b7a681ecca84b539cf74d64fd536c56709de543e2c97bc4471ab0c1700358bfc49b013713ebd9e2cc5f92294d2e5137eb38976f7ca8")
		fmt.Println("hash签名结果为")
		fmt.Println(hex.EncodeToString(sigPub2.Signature))
		sigPub2.Pubkey, _ = hex.DecodeString("02f86244be4370674f9780c0f36902dedf1d16521bae0c61438345222d932f1122")
		fmt.Println("对应的公钥为")
		fmt.Println(hex.EncodeToString(sigPub2.Pubkey))
	}

	// 签名结果返回给服务器
	// 拼接
	// 服务器收到签名结果后，回填TxHash结构体
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
	pass := VerifyRawTransaction(signedTrans, []TxUnlock{unlockData1, unlockData2}, segwit, addressPrefix)
	if pass {
		fmt.Println("验证通过!")
	} else {
		t.Error("验证失败!")
	}

}