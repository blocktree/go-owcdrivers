package bech32m

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func Test_Encode(t *testing.T) {
	hash, _ := hex.DecodeString("ecb8b85aeebbc7b7eb1b37561ae7cd508494e6a9aeb76647ed1162eaea4281ac")
	excepted := "xch1ajutskhwh0rm06cmxatp4e7d2zzffe4f46mkv3ldz93w46jzsxkqd3rtq6"
	prefix := "xch"
	charset := "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	version := []byte{0}

	address, err := Bech32mEncode(prefix, hash, version, VersionSuffix, charset)
	if err != nil {
		t.Error("decode error")
		return
	} else {
		if address != excepted {
			t.Error("result error")
			return
		}
		fmt.Println("SUCCESS")
	}
}

func Test_Decode(t *testing.T) {
	address := "xch1ajutskhwh0rm06cmxatp4e7d2zzffe4f46mkv3ldz93w46jzsxkqd3rtq6"
	prefix := "xch"
	charset := "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	excepted := "ecb8b85aeebbc7b7eb1b37561ae7cd508494e6a9aeb76647ed1162eaea4281ac"
	version := []byte{0}
	hash, err := Bech32mDecode(address, prefix, version, VersionSuffix,charset)
	if err != nil {
		t.Error("decode error")
		return
	} else {
		if hex.EncodeToString(hash) != excepted {
			t.Error("result error")
			return
		}
		fmt.Println("SUCCESS")
	}
}