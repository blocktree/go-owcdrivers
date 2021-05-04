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

	address, err := Bech32mEncode(prefix, hash, charset)
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
	hash, err := Bech32mDecode(address, prefix,charset)
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



func Test_Encode_chia_testnet(t *testing.T) {
	hash, _ := hex.DecodeString("ea2efc3186f7117223dd8f5552810a2fa5d1ad0c6385e4031bad34d421c027a5")
	prefix := "txch"
	charset := "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

	address, err := Bech32mEncode(prefix, hash, charset)
	if err != nil {
		t.Error("decode error")
		return
	} else {
		fmt.Println("SUCCESS")
		fmt.Println(address)
	}
}