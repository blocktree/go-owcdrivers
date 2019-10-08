package filenetTransaction

import (
	"encoding/hex"
	"fmt"
	"github.com/blocktree/go-owcrypt"
	"testing"
)

func TestAddress(t *testing.T) {
	address := "3YZ92rqUpjYzXDrkL41Fz89LUMYRysktyWkayNcqBnrfBXwW1mCN9QL"

	addrBytes, err := decodeAddress(address)
	if err != nil {
		t.Error(err)
	} else {
		if hex.EncodeToString(addrBytes) != "33ddd597b306a6502cfaccdf54274bbf11d43f5a" {
			t.Error("address decode failed!")
		}
	}

	chk, _ := encodeAddress(addrBytes)

	if chk != address {
		t.Error("Failed!")
	}
}

func TestEncode(t *testing.T) {
	pubkey, _ := hex.DecodeString("03bc72331fb70aacc60783d43ce0ffde4ad7796c5a72c743d00f272f187f7fe0e2")

	pubkey = owcrypt.PointDecompress(pubkey, owcrypt.ECC_CURVE_SECP256K1)[1:]

	hash := owcrypt.Hash(pubkey, 0, owcrypt.HASH_ALG_KECCAK256)[12:]

	address, _ := encodeAddress(hash)

	fmt.Println(address)
}