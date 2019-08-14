package addressEncoder

import (
	"encoding/hex"
	"fmt"
	"github.com/blocktree/go-owcdrivers/addressEncoder/bech32"
	"testing"
)

func TestBase58Decode(t *testing.T) {
	addr := "VcbvpFHqiwqbsYvaeP71Jw3a11gbCiVyPyU"
	hash, err := Base58Decode(addr, NewBase58Alphabet(BTCAlphabet))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}
	fmt.Printf("hash: %s \n", hex.EncodeToString(hash))

}


func TestBech32(t *testing.T) {
	hash,_ := hex.DecodeString("09ca6d8f32d802edd899a894172c6ea966a612c9")
	prefix := "bnb"

	addr := bech32.Encode(prefix, BTCBech32Alphabet, hash, nil)
	fmt.Println(addr)
}