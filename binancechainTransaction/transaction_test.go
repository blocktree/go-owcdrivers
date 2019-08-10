package binancechainTransaction

import (
	"encoding/hex"
	"fmt"
	"github.com/binance-chain/go-sdk/common/types"
	"github.com/binance-chain/go-sdk/keys"
	"github.com/binance-chain/go-sdk/types/msg"
	"github.com/binance-chain/go-sdk/types/tx"

	"testing"
)

func TestDecodeRawTransaction(t *testing.T) {
	trx, _ := hex.DecodeString("d101f0625dee0a562a2c87fa0a270a14da1f29aa69c73301198f469ebfdf8397a45d5ff8120f0a07434f532d3245341080f8c4844612270a148f8949f7c8ffed2e64585c607f13ffc59d8b0a98120f0a07434f532d3245341080f8c4844612710a26eb5ae98721031b4a6406411e74e9bbe90e39311a71b830d53075e27c1221920405ce3433eeb11240a29d7d62aa9d677443b976f506e1fd257a7c639539a3d830200f5cf874c2b94e7d2c5d62e3d61644cd606be25ba930b41cb9e4539c885402a36a5d2300deae751881f90220c20a2001")

	stdTx, err := DecodeRawTransaction(trx)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Println(stdTx)
	}
}

func Test_1BEAC925281B6C051AE84787024EEFCD35A25BBC647815385056D55BC2F5A084(t *testing.T) {
	from := "bnb1jxfh2g85q3v0tdq56fnevx6xcxtcnhtsmcu64m"
	to := "bnb1s664rzwpzk3jgau6ujpkl4mdgtn9ye37mrl88w"
	amount := int64(20525599)
	accountNumber := int64(51)
	sequence := int64(250999)
	source := int64(2)

	emptyTrans, hash, err := CreateEmptyTransactionAndHash(from, to, "BNB", amount, accountNumber, sequence, source,"")

	if err != nil {
		t.Error(err)
		return
	}

	fmt.Println(emptyTrans)
	fmt.Println(hash)

	signature := "7ac4ac35aaa26cdf8a0ec09de0ecac0525f7b1b1ab707e488635295edc59a2d95186201e14094583ba2c52ff79868827d686608dd4cba73af26e681f4ed6ae3a"
	pubkey := "0356e0a580389a6fd2cc91cd525c6d5a4d8054af70df17484e58678f9f574a0b4d"

	pass, signedTrans := VerifyAndCombineRawTransaction(emptyTrans, signature, pubkey)

	if pass {
		fmt.Println(signedTrans)
	} else {
		t.Error("failed")
	}
}


func TestTransferBNB( t *testing.T) {
	fromKeyManager, err := keys.NewPrivateKeyManager("7a4be77ccd436458e7fc3093d47cfa6fd27f027117c4fe026466aefe270a953a")
	if err != nil {
		t.Error(err)
		return
	}

	from := fromKeyManager.GetAddr()

	to, _ := hex.DecodeString("33b9e9c387328b16823aa9a0dbfa22c4dcacd80a")

	accountNumber := int64(208884)
	sequence := int64(0)
	sendMsg := msg.CreateSendMsg(from, types.Coins{types.Coin{Denom: "BNB", Amount: 5000000}}, []msg.Transfer{{to, types.Coins{types.Coin{Denom: "BNB", Amount: 5000000}}}})

	signMsg := tx.StdSignMsg{
		ChainID:       "Binance-Chain-Tigris",
		AccountNumber: accountNumber,
		Sequence:      sequence,
		Memo:          "",
		Msgs:          []msg.Msg{sendMsg},
		Source:        1,
	}

	signResult, err := fromKeyManager.Sign(signMsg)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("transaction to send : ", string(signResult))
}