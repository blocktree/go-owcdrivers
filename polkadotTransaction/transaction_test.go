package polkadotTransaction

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/blocktree/go-owcdrivers/polkadotTransaction/codec"
	"testing"
)


func Test_transaction(t *testing.T) {
	tx := TxStruct{
		//发送方公钥
		SenderPubkey:    "86377c388ec1afc558ef40c5edb3b4f7bba1a697b1bb711ece23fc7cdbfe2e1f",//"88dc3417d5058ec4b4503e0c12ea1a0a89be200fe98922423d4334014fa6b0ee",
		//接收方公钥
		RecipientPubkey: "88dc3417d5058ec4b4503e0c12ea1a0a89be200fe98922423d4334014fa6b0ee",
		//发送金额（最小单位）
		Amount:          12,
		//nonce
		Nonce:           1,
		//手续费（最小单位）
		Fee:             20,
		//当前高度
		BlockHeight:     1778228,
		//当前高度区块哈希
		BlockHash:       "bae19137f56d7c7bc88350131dd401c80c77ad3ffca7157bbf2d008a4d0dd8f4",
		//创世块哈希
		GenesisHash:     "b0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe",
		//spec版本
		SpecVersion:     1059,
		//Transaction版本
		TxVersion: 1,
	}

	// 创建空交易单和待签消息
	emptyTrans, message, err := tx.CreateEmptyTransactionAndMessage()
	if err != nil {
		t.Error("create failed : ", err)
		return
	}
	fmt.Println("空交易单 ： ", emptyTrans)
	fmt.Println("待签消息 ： ",message)

	// 签名
	prikey, _ := hex.DecodeString("e86bcaaab0a5aa5e3f3b0885db7e932e34eddb5a620b6bcc097a4b236a5a0354")
	signature, err := SignTransaction(message, prikey)
	if err != nil {
		t.Error("sign failed")
		return
	}
	fmt.Println("签名结果 ： ", hex.EncodeToString(signature))

	// signature, _ := hex.DecodeString("1cc69f7ba50ee37793c83d74b21f50239894e8733cdf7fd13565eded13ba97d8229fc51174035be6d4543908f58b016efd0aae137f8ad584c5540002326bc809")

	// 验签与交易单合并
	signedTrans, pass := VerifyAndCombineTransaction(emptyTrans, hex.EncodeToString(signature))
	if pass {
		fmt.Println("验签成功")
		fmt.Println("签名交易单 ： ", signedTrans)
	} else {
		t.Error("验签失败")
	}
}



func Test_json(t *testing.T)  {
	ts := TxStruct{
		SenderPubkey:    "123",
		RecipientPubkey: "",
		Amount:          0,
		Nonce:           0,
		Fee:             0,
		BlockHeight:     0,
		BlockHash:       "234",
		GenesisHash:     "345",
		SpecVersion:     0,
	}

	js, _ := json.Marshal(ts)

	fmt.Println(string(js))
}

func Test_decode(t *testing.T) {
	en, _ := codec.Encode(Compact_U32, uint64(139))
	fmt.Println(en)
}