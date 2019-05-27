package ontologyTransaction

import (
	"encoding/hex"
	"fmt"
	"testing"
)

//案例一
//ONT转账
func Test_case1(t *testing.T) {
	// 从 ATfZt5HAHrx3Xmio3Ak9rr23SyvmgNVJqU 向 ANeTozd4yxTa5nTyfc3mxzuu7RqabV1iow 转帐一个ONT
	from := "ATfZt5HAHrx3Xmio3Ak9rr23SyvmgNVJqU"
	to := "ANeTozd4yxTa5nTyfc3mxzuu7RqabV1iow"
	amount := uint64(1) // ONT为最小单位

	// 使用以上数据填充TxState结构体
	var txState TxState
	txState.From = from
	txState.To = to
	txState.Amount = amount
	//指定资产为ONT
	txState.AssetType = AssetONT

	// 指定gas相关数据
	gasPrice := uint64(0)
	gasLimit := uint64(20000)

	// 创建空交易单和哈希
	emptyTrans, txHash, err := CreateRawTransactionAndHash(gasPrice, gasLimit, txState)
	if err != nil {
		t.Error("创建空交易单失败！")
		fmt.Println(err)
	} else {
		fmt.Println("空交易单：")
		fmt.Println(emptyTrans)
		fmt.Println("用于签名的哈希：")
		fmt.Println(txHash.Hash)
		fmt.Println("对应的地址为：")
		fmt.Println(txHash.Addresses[0])
	}
	//将哈希值和对应地址发送给客户端
	//客户端根据地址获取对应私钥

	prikey := []byte{0x99, 0x8d, 0xb3, 0xbd, 0x68, 0xfd, 0x2e, 0x44, 0x88, 0xfb, 0x1d, 0xe9, 0x08, 0xf1, 0xb1, 0x77, 0x04, 0xc3, 0x9b, 0xb5, 0x6c, 0x53, 0x1d, 0x6f, 0x56, 0x74, 0x2b, 0x27, 0x7a, 0xe3, 0x77, 0x5a}

	// 签名
	sigPub, err := SignRawTransactionHash(txHash.Hash, prikey)
	if err != nil {
		t.Error("签名失败")
		fmt.Println(err)
	} else {
		fmt.Println("签名结果：")
		fmt.Println(hex.EncodeToString(sigPub.Signature))
		fmt.Println("对应公钥：")
		fmt.Println(hex.EncodeToString(sigPub.PublicKey))
	}

	// 合并交易单
	pass, signedTrans, err := VerifyAndCombineRawTransaction(emptyTrans, []SigPub{*sigPub})
	if err != nil {
		t.Error("合并交易单失败！")
		fmt.Println(err)
	} else {
		if pass {
			fmt.Println("交易单验证通过！")
		} else {
			t.Error("交易单验证失败！")
		}
		fmt.Println("合并之后的交易单：")
		fmt.Println(signedTrans)
	}

}

//案例二
//ONG转账
func Test_case2(t *testing.T) {
	// 从 ATfZt5HAHrx3Xmio3Ak9rr23SyvmgNVJqU 向 ANeTozd4yxTa5nTyfc3mxzuu7RqabV1iow 转帐一个ONG
	from := "ATfZt5HAHrx3Xmio3Ak9rr23SyvmgNVJqU"
	to := "ANeTozd4yxTa5nTyfc3mxzuu7RqabV1iow"
	amount := uint64(1000000000) // ONG精度为9

	// 使用以上数据填充TxState结构体
	var txState TxState
	txState.From = from
	txState.To = to
	txState.Amount = amount
	//指定资产为ONG
	txState.AssetType = AssetONG

	// 指定gas相关数据
	gasPrice := uint64(0)
	gasLimit := uint64(20000)

	// 创建空交易单
	emptyTrans, txHash, err := CreateRawTransactionAndHash(gasPrice, gasLimit, txState)
	if err != nil {
		t.Error("创建空交易单失败！")
		fmt.Println(err)
	} else {
		fmt.Println("空交易单：")
		fmt.Println(emptyTrans)
		fmt.Println("用于签名的哈希：")
		fmt.Println(txHash.Hash)
		fmt.Println("对应的地址为：")
		fmt.Println(txHash.Addresses[0])
	}

	//将哈希值和对应地址发送给客户端
	//客户端根据地址获取对应私钥

	prikey := []byte{0x99, 0x8d, 0xb3, 0xbd, 0x68, 0xfd, 0x2e, 0x44, 0x88, 0xfb, 0x1d, 0xe9, 0x08, 0xf1, 0xb1, 0x77, 0x04, 0xc3, 0x9b, 0xb5, 0x6c, 0x53, 0x1d, 0x6f, 0x56, 0x74, 0x2b, 0x27, 0x7a, 0xe3, 0x77, 0x5a}

	// 签名
	sigPub, err := SignRawTransactionHash(txHash.Hash, prikey)
	if err != nil {
		t.Error("签名失败")
		fmt.Println(err)
	} else {
		fmt.Println("签名结果：")
		fmt.Println(hex.EncodeToString(sigPub.Signature))
		fmt.Println("对应公钥：")
		fmt.Println(hex.EncodeToString(sigPub.PublicKey))
	}

	// 合并交易单
	pass, signedTrans, err := VerifyAndCombineRawTransaction(emptyTrans, []SigPub{*sigPub})
	if err != nil {
		t.Error("合并交易单失败！")
		fmt.Println(err)
	} else {
		if pass {
			fmt.Println("交易单验证通过！")
		} else {
			t.Error("交易单验证失败！")
		}
		fmt.Println("合并之后的交易单：")
		fmt.Println(signedTrans)
	}

}

// 案例三
// 提取账户的已解绑ONG
func Test_case3(t *testing.T) {
	// 将 ATfZt5HAHrx3Xmio3Ak9rr23SyvmgNVJqU 的已解绑ONG提取1个至自身地址
	from := "ATfZt5HAHrx3Xmio3Ak9rr23SyvmgNVJqU"
	to := from                   // 可以指定其他地址接收，一般向本身提取
	amount := uint64(1000000000) // ONG精度为9

	// 使用以上数据填充TxState结构体
	var txState TxState
	txState.From = from
	txState.To = to
	txState.Amount = amount
	//指定资产为ONG提取
	txState.AssetType = AssetONGWithdraw

	// 指定gas相关数据
	gasPrice := uint64(0)
	gasLimit := uint64(20000)

	// 创建空交易单
	emptyTrans, txHash, err := CreateRawTransactionAndHash(gasPrice, gasLimit, txState)
	if err != nil {
		t.Error("创建空交易单失败！")
		fmt.Println(err)
	} else {
		fmt.Println("空交易单：")
		fmt.Println(emptyTrans)
		fmt.Println("用于签名的哈希：")
		fmt.Println(txHash.Hash)
		fmt.Println("对应的地址为：")
		fmt.Println(txHash.Addresses[0])
	}

	//将哈希值和对应地址发送给客户端
	//客户端根据地址获取对应私钥

	prikey := []byte{0x99, 0x8d, 0xb3, 0xbd, 0x68, 0xfd, 0x2e, 0x44, 0x88, 0xfb, 0x1d, 0xe9, 0x08, 0xf1, 0xb1, 0x77, 0x04, 0xc3, 0x9b, 0xb5, 0x6c, 0x53, 0x1d, 0x6f, 0x56, 0x74, 0x2b, 0x27, 0x7a, 0xe3, 0x77, 0x5a}

	// 签名
	sigPub, err := SignRawTransactionHash(txHash.Hash, prikey)
	if err != nil {
		t.Error("签名失败")
		fmt.Println(err)
	} else {
		fmt.Println("签名结果：")
		fmt.Println(hex.EncodeToString(sigPub.Signature))
		fmt.Println("对应公钥：")
		fmt.Println(hex.EncodeToString(sigPub.PublicKey))
	}

	// 合并交易单
	pass, signedTrans, err := VerifyAndCombineRawTransaction(emptyTrans, []SigPub{*sigPub})
	if err != nil {
		t.Error("合并交易单失败！")
		fmt.Println(err)
	} else {
		if pass {
			fmt.Println("交易单验证通过！")
		} else {
			t.Error("交易单验证失败！")
		}
		fmt.Println("合并之后的交易单：")
		fmt.Println(signedTrans)
	}

}

func Test_tmp(t *testing.T) {
	from := "AQ3iZg48eCjPs2qwLtcMsMdNbNCDiYMqY5"
	to := "Ad9p5M83ZHFm82odeFJpqgmgSiJuGEf53Q"
	payer := "Ad9p5M83ZHFm82odeFJpqgmgSiJuGEf53Q"
	amount := uint64(20973900000000)

	// 使用以上数据填充TxState结构体
	var txState TxState
	txState.From = from
	txState.To = to
	txState.Payer = payer
	txState.Amount = amount
	//指定资产为ONT
	txState.AssetType = AssetONG

	// 指定gas相关数据
	gasPrice := uint64(500)
	gasLimit := uint64(20000)

	// 创建空交易单
	emptyTrans, txHash, err := CreateRawTransactionAndHash(gasPrice, gasLimit, txState)
	if err != nil {
		t.Error("创建空交易单失败！")
		fmt.Println(err)
	} else {
		fmt.Println("空交易单：")
		fmt.Println(emptyTrans)
		fmt.Println("用于签名的哈希：")
		fmt.Println(txHash.Hash)
		fmt.Println("对应的地址为：")
		fmt.Println(txHash.Addresses[0])
		fmt.Println(txHash.Addresses[1])
	}

	//将哈希值和对应地址发送给客户端
	//客户端根据地址获取对应私钥

	prikey := []byte{0x99, 0x8d, 0xb3, 0xbd, 0x68, 0xfd, 0x2e, 0x44, 0x88, 0xfb, 0x1d, 0xe9, 0x08, 0xf1, 0xb1, 0x77, 0x04, 0xc3, 0x9b, 0xb5, 0x6c, 0x53, 0x1d, 0x6f, 0x56, 0x74, 0x2b, 0x27, 0x7a, 0xe3, 0x77, 0x5a}

	// 签名
	sigPub, err := SignRawTransactionHash(txHash.Hash, prikey)
	if err != nil {
		t.Error("签名失败")
		fmt.Println(err)
	} else {
		fmt.Println("签名结果：")
		fmt.Println(hex.EncodeToString(sigPub.Signature))
		fmt.Println("对应公钥：")
		fmt.Println(hex.EncodeToString(sigPub.PublicKey))
	}

	// 合并交易单
	pass, signedTrans, err := VerifyAndCombineRawTransaction(emptyTrans, []SigPub{*sigPub, *sigPub})
	if err != nil {
		t.Error("合并交易单失败！")
		fmt.Println(err)
	} else {
		if pass {
			fmt.Println("交易单验证通过！")
		} else {
			t.Error("交易单验证失败！")
		}
		fmt.Println("合并之后的交易单：")
		fmt.Println(signedTrans)
	}

}
