package polkadotTransaction

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestGetEra(t *testing.T) {
	height := uint64(1767147)

	era := GetEra(height)

	fmt.Println(hex.EncodeToString(era))
}
