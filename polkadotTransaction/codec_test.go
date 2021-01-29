package polkadotTransaction

import (
	"fmt"
	"math/big"
	"testing"
)

func Test_Encode(t *testing.T) {
	testTable := map[uint64]string {
		1: "04",
		2: "08",
		63: "fc",
		64: "0101",
		128: "0102",
		192: "0103",
		256: "0104",
		320: "0105",
		512: "0108",
		16383: "fdff",
		16384: "02000100",
		1073741823: "feffffff",
		1073741824: "0300000040",
		4102610000: "0350dc88f4",
		14102610000: "0750c0944803",
	}

	for i, excepted := range testTable {
		if excepted != Encode(i) {
			t.Error(i, " failed")
		}
	}
}

func  TestBytesToCompactBytes(t *testing.T) {
	a := big.NewInt(14102610000)
	fmt.Println(a.BitLen())
	a.Bytes()

}