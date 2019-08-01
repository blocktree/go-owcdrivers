package zencashTransaction

import (
	"encoding/hex"
	"fmt"
	"github.com/blocktree/go-owcrypt"
	"testing"
)

func TestDecode(t *testing.T) {
	address := "zna28uDbgGdhiasAYQTm6MkEqAZjGrjVRVJ"
	hash, _ :=Decode(address, BitcoinAlphabet)
	fmt.Println(hex.EncodeToString(hash))

	chk := owcrypt.Hash(hash[:22], 0, owcrypt.HASh_ALG_DOUBLE_SHA256)

	fmt.Println(hex.EncodeToString(chk))
}
// 2089
// 62023ebfb02d2e5528aed833ccf8fedf4be3b544
// ecf01f29