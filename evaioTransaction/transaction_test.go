package evaioTransaction

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/blocktree/go-owcrypt"
	"testing"
)

func Test_case1(t *testing.T) {
	denom := "neva"
	chainID := "evaio-dev"
	accountNumber := 7
	memo := "cosmos transfer"
	sequence := 0
	from := "eva1pn80qt83wzk9w4gs3muc8hw26cexlgav75mar0"
	to := "eva1dqhtv85u4haxs73x8nntqttpy62k658hwev5k3"
	amount := int64(20000000000)

	gas := int64(200000)
	feeAmount := int64(10000000000)

	fee := NewStdFee(gas, Coins{NewCoin(denom, feeAmount)})

	messageType := "cosmos-sdk/MsgSend"
	message := []Message{NewMessage(messageType, NewMsgSend(from, to, Coins{NewCoin(denom, amount)}))}

	tx := NewTxStruct(chainID, memo, accountNumber, sequence, &fee, message)

	emptyTrans, hash, err := tx.CreateEmptyTransactionAndHash()
	if err != nil {
		t.Error("create empty transaction failed!")
	} else {
		fmt.Println("empty transaction : ", emptyTrans)
		fmt.Println("hash : ", hash)
	}

	prikey := []byte{0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0}

	sig, err := SignTransactionHash(hash, prikey)

	if err != nil {
		t.Error("sign transaction failed!")
	} else {
		fmt.Println("signature: ", sig)
	}

	// pubkey := []byte{0x03, 0x72, 0x47, 0x8b, 0xc9, 0x3a, 0xe8, 0x27, 0xa0, 0xd5, 0x8d, 0x5b, 0x1f, 0x31, 0xd1, 0x5d, 0x9d, 0x8c, 0xf2, 0x09, 0xcb, 0x1a, 0xe2, 0x04, 0x8b, 0xae, 0x54, 0x45, 0x73, 0x18, 0x19, 0xea, 0x14}
	pubkey, _ := hex.DecodeString("03d69a8432a0bcc256fd88f3f091ca70fa5d3f4ef41df3b2d39b536fe7e99c45c1")
	keyType := "tendermint/PubKeySecp256k1"
	mode := "block"
	ret, err := tx.CreateJsonForSend(sig, pubkey, keyType, mode)
	if err != nil {
		t.Error("create json for send failed!")
	} else {
		fmt.Println("transaction for send: ", ret)
	}
}

func Test_sig(t *testing.T) {
	sig, _ := base64.StdEncoding.DecodeString("JYnfVfRSAhfTwET5u+Sl+TXP70hdlFocLaZx8ggXb4BOvC5AWy4De4VuKIFljwv0wMSoN/Va5/Gjq4qacS/2Eg==")
	fmt.Println("sig : ", hex.EncodeToString(sig))

	pub, _ := base64.StdEncoding.DecodeString("AsFSyLhmG2sDmw0LEGNkMSLswgWDJ2LPI8T4XTS+ANzv")
	fmt.Println(hex.EncodeToString(pub))
	pub = owcrypt.PointDecompress(pub, owcrypt.ECC_CURVE_SECP256K1)[1:]
	fmt.Println(hex.EncodeToString(pub))

	hash, _ := hex.DecodeString("2038971d7a25019a6fbf42c81b98e7e90f5fe842ec4fe90035d4fed4ca27dec5")
	pass := owcrypt.Verify(pub, nil, 0, hash, 32, sig, owcrypt.ECC_CURVE_SECP256K1)

	fmt.Println(pass)

}


func Test_t(t *testing.T) {
	data := []byte{123, 34, 109, 111, 100, 101, 34, 58, 34, 98, 108, 111, 99, 107, 34, 44, 34, 116, 120, 34, 58, 123, 34, 109, 115, 103, 34, 58, 91, 123, 34, 116, 121, 112, 101, 34, 58, 34, 99, 111, 115, 109, 111, 115, 45, 115, 100, 107, 47, 77, 115, 103, 83, 101, 110, 100, 34, 44, 34, 118, 97, 108, 117, 101, 34, 58, 123, 34, 102, 114, 111, 109, 95, 97, 100, 100, 114, 101, 115, 115, 34, 58, 34, 101, 118, 97, 49, 112, 110, 56, 48, 113, 116, 56, 51, 119, 122, 107, 57, 119, 52, 103, 115, 51, 109, 117, 99, 56, 104, 119, 50, 54, 99, 101, 120, 108, 103, 97, 118, 55, 53, 109, 97, 114, 48, 34, 44, 34, 116, 111, 95, 97, 100, 100, 114, 101, 115, 115, 34, 58, 34, 101, 118, 97, 49, 100, 113, 104, 116, 118, 56, 53, 117, 52, 104, 97, 120, 115, 55, 51, 120, 56, 110, 110, 116, 113, 116, 116, 112, 121, 54, 50, 107, 54, 53, 56, 104, 119, 101, 118, 53, 107, 51, 34, 44, 34, 97, 109, 111, 117, 110, 116, 34, 58, 91, 123, 34, 97, 109, 111, 117, 110, 116, 34, 58, 34, 50, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 34, 44, 34, 100, 101, 110, 111, 109, 34, 58, 34, 110, 101, 118, 97, 34, 125, 93, 125, 125, 93, 44, 34, 102, 101, 101, 34, 58, 123, 34, 97, 109, 111, 117, 110, 116, 34, 58, 91, 123, 34, 97, 109, 111, 117, 110, 116, 34, 58, 34, 49, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 34, 44, 34, 100, 101, 110, 111, 109, 34, 58, 34, 110, 101, 118, 97, 34, 125, 93, 44, 34, 103, 97, 115, 34, 58, 34, 50, 48, 48, 48, 48, 48, 34, 125, 44, 34, 115, 105, 103, 110, 97, 116, 117, 114, 101, 115, 34, 58, 91, 123, 34, 112, 117, 98, 95, 107, 101, 121, 34, 58, 123, 34, 116, 121, 112, 101, 34, 58, 34, 116, 101, 110, 100, 101, 114, 109, 105, 110, 116, 47, 80, 117, 98, 75, 101, 121, 83, 101, 99, 112, 50, 53, 54, 107, 49, 34, 44, 34, 118, 97, 108, 117, 101, 34, 58, 34, 65, 115, 70, 83, 121, 76, 104, 109, 71, 50, 115, 68, 109, 119, 48, 76, 69, 71, 78, 107, 77, 83, 76, 115, 119, 103, 87, 68, 74, 50, 76, 80, 73, 56, 84, 52, 88, 84, 83, 43, 65, 78, 122, 118, 34, 125, 44, 34, 115, 105, 103, 110, 97, 116, 117, 114, 101, 34, 58, 34, 54, 117, 48, 81, 110, 72, 116, 119, 80, 49, 82, 98, 110, 43, 50, 83, 65, 69, 89, 90, 74, 70, 57, 113, 70, 71, 107, 55, 116, 109, 107, 87, 112, 103, 106, 55, 112, 102, 121, 75, 53, 76, 57, 50, 109, 47, 67, 51, 84, 83, 51, 50, 72, 83, 110, 86, 74, 119, 121, 111, 99, 102, 108, 116, 105, 83, 119, 82, 112, 88, 112, 85, 84, 102, 99, 109, 111, 101, 80, 100, 99, 56, 68, 110, 122, 65, 61, 61, 34, 125, 93, 44, 34, 109, 101, 109, 111, 34, 58, 34, 99, 111, 115, 109, 111, 115, 32, 116, 114, 97, 110, 115, 102, 101, 114, 34, 125, 125}
	fmt.Println(string(data))
}