package evaioTransaction

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func Test_ATOMAddress(t *testing.T) {
	hash, _ := hex.DecodeString("3335a8768bf87fbd1e554e71a82da2809110e190")
	address := Bech32Encode("cosmos", ATOMBech32Alphabet, hash)

	if address != "cosmos1xv66sa5tlplm68j4fec6stdzszg3pcvswag06j" {
		t.Error("atom address encode failed!")
	} else {
		fmt.Println("atom address encode success!")
		fmt.Println(address)
	}

	check, err := Bech32Decode(address)

	if err != nil {
		t.Error("atom address decode failed!")
	} else {
		for index := 0; index < 20; index++ {
			if check[index] != hash[index] {
				t.Error("atom address decode failed!")
			}
		}
		fmt.Println("atom address decode success!")
	}
}
