package aliencoinTransaction

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func Test_send(t *testing.T) {
	// 该案例参照链上交易 03e5032a0b99dbea17e9f3665d7dee22b4632f8cdd6150fed8c87dbc485f36f3 进行构建

	txid := "03e5032a0b99dbea17e9f3665d7dee22b4632f8cdd6150fed8c87dbc485f36f3"
	vout := uint32(0)
	lockScript := "76a914e6abcb20945486c8c5432e518d29d140f3c0daeb88ac"

	to1 := "ASoPDMzv6C6ZkZaeYCFMaHgGzSUKezRze2"
	amount1 := uint64(31798399988116)
	to2 := "AQhxgsCGDUq8oiWCK96RAaeDyJmQ924irK"
	amount2 := uint64(1000)

	// 构建输入
	vins := []Vin{Vin{txid, vout, lockScript}}
	// 构建输出
	vouts := []Vout{Vout{to1, amount1}, Vout{to2, amount2}}

	//其他参数
	lockTime := uint32(0)

	// 构建交易单和待签哈希
	emptyTrans, hashes, err := CreateEmptyTransactionAndHash(vins, vouts, lockTime)
	if err != nil {
		t.Error("create failed!")
		return
	} else {
		fmt.Println("空交易单:\n", emptyTrans)
		fmt.Println("待签哈希:\n", hashes[0])
	}

	// 对交易单签名
	prikey := []byte{0x84, 0x98, 0x23, 0xd2, 0x2d, 0x81, 0xe4, 0x9e, 0xb7, 0x19, 0x06, 0x6b, 0xcf, 0x7e, 0xd1, 0x73, 0xe6, 0x09, 0x48, 0x22, 0xb0, 0xea, 0x4e, 0x79, 0x3f, 0x1d, 0x85, 0x97, 0xa5, 0x06, 0x0d, 0x27}
	signature, err := SignTransaction(hashes[0], prikey)
	if err != nil {
		t.Error("failed to sign!")
	} else {
		// only for test
		signature, _ := hex.DecodeString("178d596dff077d60aeedd654b611e0e186211e0a2f776d22e28008a7694f197d3250f8d4f99a70cb7bf92bb3b3aaa3925115749b6ce1c4f2d8b03935f43d5c4f")
		fmt.Println("签名结果:\n", hex.EncodeToString(signature))
	}

	// 验证合并
	pubkey, _ := hex.DecodeString("03561fe30b5a25d4b458bb65394a84061978924938914d688debbe52ebfcdadbba")

	//构建签名
	sigPubs := []SigPub{SigPub{pubkey, signature}}

	pass, signedTrans, err := VerifyAndCombineTransaction(emptyTrans, sigPubs)
	if err != nil {
		t.Error("failed to verify!")
	} else {
		if pass != true {
			fmt.Println("verify failed!")
		} else {
			fmt.Println("待发送交易单:\n", signedTrans)
		}
	}
}
