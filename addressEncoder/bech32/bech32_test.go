package bech32

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func Test_bech32_address(t *testing.T) {
	address := "bc1qvgclzqz7smqr6haag9mknpwsjnxtdqkncr64kd"
	ret, err := Decode(address, "qpzry9x8gf2tvdw0s3jn54khce6mua7l")
	if err != nil {
		t.Error("decode error")
	} else {
		fmt.Println(hex.EncodeToString(ret))
	}

	addresschk := Encode("bc", "qpzry9x8gf2tvdw0s3jn54khce6mua7l", ret, nil)
	if addresschk != address {
		t.Error("encode error")
	} else {
		fmt.Println(addresschk)
	}

}

func Test_xch(t *testing.T) {
	address := "xch1ajutskhwh0rm06cmxatp4e7d2zzffe4f46mkv3ldz93w46jzsxkqd3rtq6"
	ret, err := Decode(address, "qpzry9x8gf2tvdw0s3jn54khce6mua7l")

	fmt.Println(hex.EncodeToString(ret))
	fmt.Println(err)
}