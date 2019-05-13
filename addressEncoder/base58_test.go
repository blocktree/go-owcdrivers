package addressEncoder

import (
	"encoding/hex"
	"fmt"
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
