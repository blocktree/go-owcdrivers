package zencashTransaction

import (
	"encoding/hex"
	"fmt"
	"github.com/blocktree/go-owcrypt"
	"testing"
)

func TestDecode(t *testing.T) {
	address := "znowCwfo4iz7mfndyqH4F2JLbWy19fESBsd"
	hash, _ :=Decode(address, BitcoinAlphabet)
	fmt.Println(hex.EncodeToString(hash))

	chk := owcrypt.Hash(hash[:22], 0, owcrypt.HASH_ALG_DOUBLE_SHA256)

	fmt.Println(hex.EncodeToString(chk))


}

func Test_tmp(t *testing.T) {
	data, _ := hex.DecodeString("5230ff2fd4a08b46c9708138ba45d4ed480aed088402d81dce274ecf01000000")
	fmt.Println(hex.EncodeToString(reverseBytes(data)))


	hash, _ := hex.DecodeString("faa54cf3b138bd587a7a12b1b2ca76d600a37ae3")
	fmt.Println(EncodeCheck(ZENMainnetAddressPrefix.P2PKHPrefix, hash))
}