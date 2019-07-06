package owkeychain

import (
	"fmt"
	"testing"
)

func Test_chainencode(t *testing.T) {
	owpub := "owpubeyoV6FsQ8AAx5VjEQvV1FyQjkEhf3aP3EifHiDok2wv53GHeUq12tUAFvyMPrzrJA5tvVYDdsjgTrXDSuo4poZXrtHACCsLq3NegLGtvbq27VkNKB"

	extendKey, err := OWDecode(owpub)
	if err != nil {
		t.Error(err)
	}

	owchain, err := GetMultiSigShareData(owpub)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Println(owchain)
	}

	ms, err := ChainDecode(owchain)
	if err != nil {
		t.Error(err)
	}

	for index := 0; index < len(ms.Pubkey); index++ {
		if ms.Pubkey[index] != extendKey.key[index] {
			t.Error("decode key failed!")
		}
	}

	for index := 0; index < 32; index++ {
		if ms.ChainCode[index] != extendKey.chainCode[index] {
			t.Error("decode chaincode failed!")
		}
	}

	if ms.CurveType != extendKey.curveType {
		t.Error("decode curvetype failed!")
	}

	chk := ms.ChianEncode()

	if chk != owchain {
		t.Error("encode failed!")
	} else {
		fmt.Println("success!")
	}
}
