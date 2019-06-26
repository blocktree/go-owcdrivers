package rippleTransaction

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func Test_enc(t *testing.T) {
	fmt.Println("MemoType   : ", hex.EncodeToString(getEncBytes(encodings["MemoType"])))
	fmt.Println("MemoData   : ", hex.EncodeToString(getEncBytes(encodings["MemoData"])))
	fmt.Println("MemoFormat : ", hex.EncodeToString(getEncBytes(encodings["MemoFormat"])))
}
