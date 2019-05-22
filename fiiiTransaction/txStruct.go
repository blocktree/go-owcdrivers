package fiiiTransaction

import (
	"encoding/binary"
	"encoding/hex"
	"strings"

	owcrypt "github.com/blocktree/go-owcrypt"
)

type TransactionMsg struct {
	Version     int         `json:"Version"`
	Hash        string      `json:"Hash"`
	Timestamp   int64       `json:"Timestamp"`
	LockTime    int64       `json:"Locktime"`
	ExpiredTime int64       `json:"ExpiredTime"`
	InputCount  int         `json:"InputCount"`
	OutputCount int         `json:"OutputCount"`
	Inputs      []InputMsg  `json:"Inputs"`
	Outputs     []OutputMsg `json:"Outputs"`
	Size        int         `json:"Size"`
}

func (tm *TransactionMsg) Complete() {
	txBytes := []byte{}

	timestamp := make([]byte, 8)
	lockTime := make([]byte, 8)
	expiredTime := make([]byte, 8)
	totleInput := make([]byte, 4)
	totleOutput := make([]byte, 4)

	binary.BigEndian.PutUint64(timestamp, uint64(tm.Timestamp))
	binary.BigEndian.PutUint64(lockTime, uint64(tm.LockTime))
	binary.BigEndian.PutUint64(expiredTime, uint64(tm.ExpiredTime))
	binary.BigEndian.PutUint32(totleInput, uint32(tm.InputCount))
	binary.BigEndian.PutUint32(totleOutput, uint32(tm.OutputCount))

	txBytes = append(txBytes, timestamp...)
	txBytes = append(txBytes, lockTime...)
	txBytes = append(txBytes, expiredTime...)
	txBytes = append(txBytes, totleInput...)

	for _, in := range tm.Inputs {
		txBytes = append(txBytes, in.ToBytes()...)
	}

	txBytes = append(txBytes, totleOutput...)

	for _, out := range tm.Outputs {
		txBytes = append(txBytes, out.ToBytes()...)
	}

	tm.Hash = strings.ToUpper(hex.EncodeToString(owcrypt.Hash(txBytes, 0, owcrypt.HASH_ALG_SHA256)))

	tm.Size = len(txBytes) + 4 /*version*/ + 32 /*hash*/

}
