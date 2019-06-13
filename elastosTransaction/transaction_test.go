package elastosTransaction

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func Test_01(t *testing.T) {
	// 模拟链上交易  4567fcebee78e80611c84c1f1bf442c3b867f3f4445100e2e6ae252bc9390a4d

	// 前置交易
	txid := "096d065ddbba52739bbab781ef4632373528c7e30bc8d7f2d27fd0696250f7ee"
	vout := uint16(1)
	address := "Eb1r8zaS3qbsRFH4j4GADshJCqFZ84ZM8u"

	// 构造输入
	vins := []Vin{Vin{
		TxID:    txid,
		Vout:    vout,
		Address: address,
	}}

	// 输出
	to1 := "EUk5fYxedfzKveD1h8hG8W3c5axFnsv29p"
	amount1 := uint64(3000000000)

	to2 := "EZqDb1azcmVcfJs2HU9sriH8P6JQuENreh"
	amount2 := uint64(110999990280)

	//构造输出
	out1 := Vout{
		AssetID: AssetID_ELA,
		Amount:  amount1,
		Address: to1,
	}

	out2 := Vout{
		AssetID: AssetID_ELA,
		Amount:  amount2,
		Address: to2,
	}

	vouts := []Vout{out1, out2}

	// 创建空交易单和待签哈希
	emptyTrans, txHashes, err := CreateEmptyRawTransactionAndHash(vins, vouts)

	if err != nil {
		t.Error(err)
	} else {
		fmt.Println("空交易单:\n", emptyTrans)
		for i, hash := range txHashes {
			fmt.Println("第", i, "个待签哈希为:\n"+hash.Hash+"\n对应的地址为:\n"+hash.Address)
		}
	}

	//  对待签哈希计算签名
	prikey := []byte{0x84, 0x98, 0x23, 0xd2, 0x2d, 0x81, 0xe4, 0x9e, 0xb7, 0x19, 0x06, 0x6b, 0xcf, 0x7e, 0xd1, 0x73, 0xe6, 0x09, 0x48, 0x22, 0xb0, 0xea, 0x4e, 0x79, 0x3f, 0x1d, 0x85, 0x97, 0xa5, 0x06, 0x0d, 0x27}
	signature, err := SignRawTransaction(txHashes[0].Hash, prikey)
	if err != nil {
		t.Error(err)
	} else {
		signature, _ = hex.DecodeString("a089aad77411f86a8e949396748102abef8f728d2eb4fefd9985858fa17b4a7dc2e4acbb2c6c18f40bbefc0bb449da241974b8af7a71710fc7b9fd8f4afd2198")
		fmt.Println("签名结果:\n", hex.EncodeToString(signature))
	}

	// 填充对应公钥,验证并合并交易单
	pubkey, _ := hex.DecodeString("026763900c4fcba778fc738c430b33a342e389c28c339e2932fab029d72cfc28dc")

	sigPub := SigPub{
		PublicKey: pubkey,
		Signature: signature,
	}
	pass, signedTrans := VerifyAndCombineRawTransaction(emptyTrans, []SigPub{sigPub})
	if !pass {
		t.Error("交易单验签失败!")
	} else {
		fmt.Println("合并后的交易单:\n" + signedTrans)
	}
}

func Test_02(t *testing.T) {
	// 模拟链上交易  93e21aef684bf40a4634292950952713da89c2cb8a629e5b87a3d2be63d7364d
	txid1 := "4a2873ac13cbac50eda3d120ff9c0b2f19e7e0e0bdd7b4397e360f3560187589"
	vout1 := uint16(0)
	address1 := "EPab1kv9vs2tTwcrikKsufGBAsBULqWLnV"
	in1 := Vin{txid1, vout1, address1}

	txid2 := "ede523c09c8e0ef7b65d3676d9f78252dadea2b42133961f6d14da31a46cd883"
	vout2 := uint16(84)
	address2 := "EMSbGfChM4L2icoW4ZC6wrZkijmGrgxCtg"
	in2 := Vin{txid2, vout2, address2}

	txid3 := "636947359c5a72197e7753774a5115d11df213f99a23e224bb6d246ee515961e"
	vout3 := uint16(84)
	address3 := "EMSbGfChM4L2icoW4ZC6wrZkijmGrgxCtg"
	in3 := Vin{txid3, vout3, address3}

	vins := []Vin{in1, in2, in3}

	to1 := "EQaC7tZvmbiKoyQc1bTzEePFKS6t99wTLg"
	amount1 := uint64(89571000)
	out1 := Vout{AssetID_ELA, amount1, to1}

	to2 := "EbTiNod8a7ePdeE2hH61aEPTmgyLtWbJxv"
	amount2 := uint64(52000000000)
	out2 := Vout{AssetID_ELA, amount2, to2}

	vouts := []Vout{out1, out2}

	// 创建空交易单和待签哈希
	emptyTrans, txHashes, err := CreateEmptyRawTransactionAndHash(vins, vouts)

	if err != nil {
		t.Error(err)
	} else {
		fmt.Println("空交易单:\n", emptyTrans)
		for i, hash := range txHashes {
			fmt.Println("第", i, "个待签哈希为:\n"+hash.Hash+"\n对应的地址为:\n"+hash.Address)
		}
	}

	//  对待签哈希计算签名
	prikey1 := []byte{0x84, 0x98, 0x23, 0xd2, 0x2d, 0x81, 0xe4, 0x9e, 0xb7, 0x19, 0x06, 0x6b, 0xcf, 0x7e, 0xd1, 0x73, 0xe6, 0x09, 0x48, 0x22, 0xb0, 0xea, 0x4e, 0x79, 0x3f, 0x1d, 0x85, 0x97, 0xa5, 0x06, 0x0d, 0x27}
	signature1, err := SignRawTransaction(txHashes[0].Hash, prikey1)
	if err != nil {
		t.Error(err)
	} else {
		signature1, _ = hex.DecodeString("d998230cd55044df1e575ae3ce1508e7440585d425f1fa9dfde26b7fb0e3d70785bfe8b8b3d5c834c9442eb18c0d91793ae134fbecf0c72ef487e8d15eae78e3")
		fmt.Println("签名结果:\n", hex.EncodeToString(signature1))
	}

	prikey2 := []byte{0x84, 0x98, 0x23, 0xd2, 0x2d, 0x81, 0xe4, 0x9e, 0xb7, 0x19, 0x06, 0x6b, 0xcf, 0x7e, 0xd1, 0x73, 0xe6, 0x09, 0x48, 0x22, 0xb0, 0xea, 0x4e, 0x79, 0x3f, 0x1d, 0x85, 0x97, 0xa5, 0x06, 0x0d, 0x27}
	signature2, err := SignRawTransaction(txHashes[1].Hash, prikey2)
	if err != nil {
		t.Error(err)
	} else {
		signature2, _ = hex.DecodeString("68ce5dad27f87684341c5a6b5be8e6b634c24be9e24f850cd480ad5c0630730c6beb9d334ad405a7fd3c7ec3eac4dd0e27dd50d4854b186d7357eb1147f81dc1")
		fmt.Println("签名结果:\n", hex.EncodeToString(signature2))
	}

	// 填充对应公钥,验证并合并交易单
	pubkey1, _ := hex.DecodeString("02c7cd1fe7bcf4bb786e758cc989c8e63df290c4c6f8648c37a89f8394508e444a")

	sigPub1 := SigPub{
		PublicKey: pubkey1,
		Signature: signature1,
	}

	pubkey2, _ := hex.DecodeString("035fda0530ebfd087d72835d242fc359dd01f898cd48d9de5f7c2fc15c8f01be94")

	sigPub2 := SigPub{
		PublicKey: pubkey2,
		Signature: signature2,
	}

	pass, signedTrans := VerifyAndCombineRawTransaction(emptyTrans, []SigPub{sigPub1, sigPub2})
	if !pass {
		t.Error("交易单验签失败!")
	} else {
		fmt.Println("合并后的交易单:\n" + signedTrans)
	}
}
