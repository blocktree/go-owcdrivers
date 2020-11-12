package mateverseTransaction

import (
	"fmt"
	"testing"
)

// 测试链上交易 txid = e70500e9e10128f61b290f8b2219167a89a5c25eb00b5c4c8775c3d150d46636
func Test_e70500e9e10128f61b290f8b2219167a89a5c25eb00b5c4c8775c3d150d46636(t *testing.T) {
	// 节点构建的空交易单
	emptyTrans := "0400000001754366e7d44b79b3c1fdbbdf845be3469e7d6d83cf641a8aa5bc999e2c4071250100000000ffffffff0237ecfc05000000001976a914eed60abab201e188671e43e593c85066ff4260db88ac0100000000000000ab929b00000000001976a91459d20a7a09e90eccd7e61f5866a30ef291f98f2288ac010000000000000000000000"

	// 1 . 从空交易单中提取输入信息
	inputs, err := GetInputsFromEmptyRawTransaction(emptyTrans)
	if err != nil {
		t.Error(err)
		return
	} else {
		// 通过返回结果来获取前置交易的TxID和Vout
		for i, input := range inputs {
			fmt.Println("====================第 ", i, " 个输入====================")
			fmt.Println("TxID  :  ", input.GetTxID())
			fmt.Println("Vout  :  ", input.GetVout())
		}
	}

	// 交易共有 1 个输入， 通过 txid 和 vout 获取对应的锁定脚本
	lockScript := "dup hash160 [ 59d20a7a09e90eccd7e61f5866a30ef291f98f22 ] equalverify checksig"
	// 设定锁定脚本
	inputs[0].SetLockScript(lockScript)

	// 2 . 获取待签哈希
	err = GetSigHash(emptyTrans, &inputs)
	if err != nil {
		t.Error(err)
		return
	} else {
		for i, input := range inputs {
			fmt.Println("====================第 ", i, " 个输入的待签哈希====================")
			fmt.Println("hash  :  ", input.GetHash())
		}
	}

	//	3 . 完成签名
	prikey := []byte{0x80, 0xbc, 0x39, 0x8d, 0x7c, 0x4a, 0x67, 0x4d, 0xaa, 0x97, 0x75, 0x66, 0xc2, 0xe6, 0xcd, 0x50, 0x40, 0x52, 0x00, 0x27, 0xe5, 0x7f, 0xe8, 0x06, 0xdf, 0xaa, 0x86, 0x8d, 0xf4, 0xcc, 0x43, 0xab}

	signature, err := SignTransaction(inputs[0].GetHash(), prikey)
	if err != nil {
		t.Error(err)
		return
	} else {
		signature = "6afd92e3a91948efb5e8c9cdeb8dc18692a3d6bc9b2b3f3ae7d69a82135c839c7d400f79897f52a9216cd18312feb1fde39b0db56a6f9aa5a1ba21aa54f48794"
		fmt.Println("====================第 0 个输入的签名结果====================")
		fmt.Println("signature : ", signature)
	}

	// 4 . 填入公钥和签名
	pubkey := "033a67f19bad4eab86ffade1bd050885e205562e07f8ebb50a114eb15b233a3b86"
	inputs[0].SetPubKey(pubkey)
	inputs[0].SetSignature(signature)

	// 5 . 验证签名并合成交易单
	pass, signedTrans := VerifyAndCombineTransaction(emptyTrans, inputs)
	if pass {
		fmt.Println("====================合并之后的交易单====================")
		fmt.Println(signedTrans)
		fmt.Println("验签成功!")
	} else {
		t.Error("签名合成失败！")
		return
	}
}

// 测试链上交易 txid = bfa05fd6b0ab2863f749923bb0cccbbde0d68a4167136f60d3bf24c73c348562
func Test_bfa05fd6b0ab2863f749923bb0cccbbde0d68a4167136f60d3bf24c73c348562(t *testing.T) {
	// 节点构建的空交易单
	emptyTrans := "0400000002f80e5bbecbe76e42e75baf4458f5492f22bf220f650c067ce02f4e7117985bdb0100000000ffffffff7f6ea57e8fc8e2336debdfedacb440d13eb510ceb09e8b79f16e016100606b6a0000000000ffffffff02a615b20a000000001976a9141bd9a19573fc5c3f2036262c3eec0aade1dfd9db88ac0100000000000000b6001206000000001976a91459d20a7a09e90eccd7e61f5866a30ef291f98f2288ac010000000000000000000000"

	// 1 . 从空交易单中提取输入信息
	inputs, err := GetInputsFromEmptyRawTransaction(emptyTrans)
	if err != nil {
		t.Error(err)
		return
	} else {
		// 通过返回结果来获取前置交易的TxID和Vout
		for i, input := range inputs {
			fmt.Println("====================第 ", i, " 个输入====================")
			fmt.Println("TxID  :  ", input.GetTxID())
			fmt.Println("Vout  :  ", input.GetVout())
		}
	}

	// 交易共有 2 个输入， 通过 txid 和 vout 获取对应的锁定脚本
	lockScript1 := "dup hash160 [ 59d20a7a09e90eccd7e61f5866a30ef291f98f22 ] equalverify checksig"
	lockScript2 := "dup hash160 [ 59d20a7a09e90eccd7e61f5866a30ef291f98f22 ] equalverify checksig"
	// 设定锁定脚本
	inputs[0].SetLockScript(lockScript1)
	inputs[1].SetLockScript(lockScript2)

	// 2 . 获取待签哈希
	err = GetSigHash(emptyTrans, &inputs)
	if err != nil {
		t.Error(err)
		return
	} else {
		for i, input := range inputs {
			fmt.Println("====================第 ", i, " 个输入的待签哈希====================")
			fmt.Println("hash  :  ", input.GetHash())
		}
	}

	//	3 . 完成签名
	prikey1 := []byte{0x80, 0xbc, 0x39, 0x8d, 0x7c, 0x4a, 0x67, 0x4d, 0xaa, 0x97, 0x75, 0x66, 0xc2, 0xe6, 0xcd, 0x50, 0x40, 0x52, 0x00, 0x27, 0xe5, 0x7f, 0xe8, 0x06, 0xdf, 0xaa, 0x86, 0x8d, 0xf4, 0xcc, 0x43, 0xab}
	prikey2 := []byte{0x80, 0xbc, 0x39, 0x8d, 0x7c, 0x4a, 0x67, 0x4d, 0xaa, 0x97, 0x75, 0x66, 0xc2, 0xe6, 0xcd, 0x50, 0x40, 0x52, 0x00, 0x27, 0xe5, 0x7f, 0xe8, 0x06, 0xdf, 0xaa, 0x86, 0x8d, 0xf4, 0xcc, 0x43, 0xab}

	signature1, err := SignTransaction(inputs[0].GetHash(), prikey1)
	if err != nil {
		t.Error(err)
		return
	} else {
		signature1 = "a630db94e88270af4e845a8f0aca19f0debabb9048971b12c4d95222b562c2c854c31462d66353786ccb829a6b762f7d039a818ed5b41b80fd548b7df22f4f87"
		fmt.Println("====================第 0 个输入的签名结果====================")
		fmt.Println("signature : ", signature1)
	}

	signature2, err := SignTransaction(inputs[1].GetHash(), prikey2)
	if err != nil {
		t.Error(err)
		return
	} else {
		signature2 = "1602907706f20dc8ee396b527e41d7d9fdf6d2dddba9f7e4f7401e86c0e34c0a726d36562c4c9b665f07179dad92e51ae59abc271c9105361528e4172c660dc0"
		fmt.Println("====================第 1 个输入的签名结果====================")
		fmt.Println("signature : ", signature2)
	}

	// 4 . 填入公钥和签名
	pubkey1 := "033a67f19bad4eab86ffade1bd050885e205562e07f8ebb50a114eb15b233a3b86"
	pubkey2 := "033a67f19bad4eab86ffade1bd050885e205562e07f8ebb50a114eb15b233a3b86"
	inputs[0].SetPubKey(pubkey1)
	inputs[0].SetSignature(signature1)
	inputs[1].SetPubKey(pubkey2)
	inputs[1].SetSignature(signature2)

	// 5 . 验证签名并合成交易单
	pass, signedTrans := VerifyAndCombineTransaction(emptyTrans, inputs)
	if pass {
		fmt.Println("====================合并之后的交易单====================")
		fmt.Println(signedTrans)
		fmt.Println("验签成功!")
	} else {
		t.Error("签名合成失败！")
		return
	}
}

// 测试链上交易 txid = 2b8e090dc8a12df7bd44a23bc797a63efb727f560f86ddf7d5de80336a115b20
func Test_2b8e090dc8a12df7bd44a23bc797a63efb727f560f86ddf7d5de80336a115b20(t *testing.T) {
	// 节点构建的空交易单
	emptyTrans := "0400000003a711fbfeeca64eebfefedbfd96cd9d88e8ce98e4f199f4d9d9aa9150d4a1ab8c0000000000ffffffffa711fbfeeca64eebfefedbfd96cd9d88e8ce98e4f199f4d9d9aa9150d4a1ab8c0100000000ffffffffa711fbfeeca64eebfefedbfd96cd9d88e8ce98e4f199f4d9d9aa9150d4a1ab8c0200000000ffffffff0200000000000000001976a9145d73a01dc8cb4d8609636c4b4480a8ceb35e02d888ac01000000020000000200000003444e418cb5873001000000a022c223020000001976a914417699cb6919468f8f7e835aabd44b588200cec988ac010000000000000000000000"

	// 1 . 从空交易单中提取输入信息
	inputs, err := GetInputsFromEmptyRawTransaction(emptyTrans)
	if err != nil {
		t.Error(err)
		return
	} else {
		// 通过返回结果来获取前置交易的TxID和Vout
		for i, input := range inputs {
			fmt.Println("====================第 ", i, " 个输入====================")
			fmt.Println("TxID  :  ", input.GetTxID())
			fmt.Println("Vout  :  ", input.GetVout())
		}
	}

	// 交易共有 2 个输入， 通过 txid 和 vout 获取对应的锁定脚本
	lockScript1 := "[ 504e3d303b4c483d31303b545950453d313b4c513d31303030303b4c503d31303b554e3d31 ] [ 0000000000000000000000000000000000000000000000000000000000000000ffffffff ] checkattenuationverify dup hash160 [ 687125fe419e558afc0abf4f1f96096784db5f40 ] equalverify checksig"
	lockScript2 := "dup hash160 [ 417699cb6919468f8f7e835aabd44b588200cec9 ] equalverify checksig"
	lockScript3 := "dup hash160 [ 417699cb6919468f8f7e835aabd44b588200cec9 ] equalverify checksig"
	// 设定锁定脚本
	inputs[0].SetLockScript(lockScript1)
	inputs[1].SetLockScript(lockScript2)
	inputs[2].SetLockScript(lockScript3)

	// 2 . 获取待签哈希
	err = GetSigHash(emptyTrans, &inputs)
	if err != nil {
		t.Error(err)
		return
	} else {
		for i, input := range inputs {
			fmt.Println("====================第 ", i, " 个输入的待签哈希====================")
			fmt.Println("hash  :  ", input.GetHash())
		}
	}

	//	3 . 完成签名
	prikey1 := []byte{0x80, 0xbc, 0x39, 0x8d, 0x7c, 0x4a, 0x67, 0x4d, 0xaa, 0x97, 0x75, 0x66, 0xc2, 0xe6, 0xcd, 0x50, 0x40, 0x52, 0x00, 0x27, 0xe5, 0x7f, 0xe8, 0x06, 0xdf, 0xaa, 0x86, 0x8d, 0xf4, 0xcc, 0x43, 0xab}
	prikey2 := []byte{0x80, 0xbc, 0x39, 0x8d, 0x7c, 0x4a, 0x67, 0x4d, 0xaa, 0x97, 0x75, 0x66, 0xc2, 0xe6, 0xcd, 0x50, 0x40, 0x52, 0x00, 0x27, 0xe5, 0x7f, 0xe8, 0x06, 0xdf, 0xaa, 0x86, 0x8d, 0xf4, 0xcc, 0x43, 0xab}
	prikey3 := []byte{0x80, 0xbc, 0x39, 0x8d, 0x7c, 0x4a, 0x67, 0x4d, 0xaa, 0x97, 0x75, 0x66, 0xc2, 0xe6, 0xcd, 0x50, 0x40, 0x52, 0x00, 0x27, 0xe5, 0x7f, 0xe8, 0x06, 0xdf, 0xaa, 0x86, 0x8d, 0xf4, 0xcc, 0x43, 0xab}

	signature1, err := SignTransaction(inputs[0].GetHash(), prikey1)
	if err != nil {
		t.Error(err)
		return
	} else {
		signature1 = "bbd3dcace7307530b1f8ba5f6a236e2cbe5d247f7918b528f61d52ba04b2b306494a7f749b361e552ab49c5e2f3d1e4fd23ee09f6d45fd941cc11b0a117bbfa7"
		fmt.Println("====================第 0 个输入的签名结果====================")
		fmt.Println("signature : ", signature1)
	}

	signature2, err := SignTransaction(inputs[1].GetHash(), prikey2)
	if err != nil {
		t.Error(err)
		return
	} else {
		signature2 = "f8fdf366e1f9621efb9eb91e7f879eaea1b7b8429647555c965bf281fe6c5f9321ba1f2fddd6823f2e2fe896b77ed79d335c063944b810e711f557346849463d"
		fmt.Println("====================第 1 个输入的签名结果====================")
		fmt.Println("signature : ", signature2)
	}

	signature3, err := SignTransaction(inputs[1].GetHash(), prikey3)
	if err != nil {
		t.Error(err)
		return
	} else {
		signature3 = "d1cb5ec401f42a60662ea02af3681d758b18ba86a41c773f61469ad586cb05e4187c66b8a76f2d2542cc8260575cd5701d977dd9b89c516254a94558ab677898"
		fmt.Println("====================第 2 个输入的签名结果====================")
		fmt.Println("signature : ", signature2)
	}

	// 4 . 填入公钥和签名
	pubkey1 := "03081f9ede5e6703a3788e390b0cb6857b63d8c25b22d8d036cd141ae4f3ff2440"
	pubkey2 := "02a3acd7dd1d8f5babbf839fb0ef08e9b26ef4f7cf6504fc785cab145a7d2baedf"
	pubkey3 := "02a3acd7dd1d8f5babbf839fb0ef08e9b26ef4f7cf6504fc785cab145a7d2baedf"
	inputs[0].SetPubKey(pubkey1)
	inputs[0].SetSignature(signature1)
	inputs[1].SetPubKey(pubkey2)
	inputs[1].SetSignature(signature2)
	inputs[2].SetPubKey(pubkey3)
	inputs[2].SetSignature(signature3)

	// 5 . 验证签名并合成交易单
	pass, signedTrans := VerifyAndCombineTransaction(emptyTrans, inputs)
	if pass {
		fmt.Println("====================合并之后的交易单====================")
		fmt.Println(signedTrans)
		fmt.Println("验签成功!")
	} else {
		t.Error("签名合成失败！")
		return
	}
}



