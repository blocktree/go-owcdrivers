package bigbangTransaction

import (
	"encoding/hex"
	"errors"
	"github.com/blocktree/go-owcrypt"
	"time"
)

type Vin struct {
	TxID string
	Vout byte
}

func CreateEmptyTransactionAndHash(lockUntil uint32, anchor string, inputs []Vin, to string, amount, fee uint64, data string) (string, string, error) {
	timestamp := uint32(time.Now().Unix())

	tx, err := NewTxStruct(DefaultVersion, TxType_Token, timestamp, lockUntil, anchor, inputs, to, amount, fee, data)
	if err != nil {
		return "", "", err
	}

	return hex.EncodeToString(tx.ToBytes()), hex.EncodeToString(tx.GetHash()), nil
}

func SignTransactionHash(hash string, prikey []byte) (string, error) {
	hashBytes, err := hex.DecodeString(hash)
	if err != nil || len(hashBytes) != 32 {
		return "", errors.New("Invalid transaction hex string!")
	}

	if prikey == nil || len(prikey) != 32 {
		return "", errors.New("Invalid prikey data!")
	}

	signature, retCode := owcrypt.Signature(prikey, nil, 0, hashBytes, 32, owcrypt.ECC_CURVE_ED25519)

	if retCode != owcrypt.SUCCESS {
		return "", errors.New("Transaction sign failed")
	}

	return hex.EncodeToString(signature), nil
}

func VerifyAndCombineTransaction(emptyTrans, signature string, pubkey []byte) (bool, string) {
	trans, err := hex.DecodeString(emptyTrans)
	if err != nil || len(trans) == 0 {
		return false, ""
	}

	sig, err := hex.DecodeString(signature)
	if err != nil || len(sig) != 64 {
		return false, ""
	}

	if pubkey == nil || len(pubkey) != 32 {
		return false, ""
	}

	if owcrypt.SUCCESS != owcrypt.Verify(pubkey, nil, 0, owcrypt.Hash(trans, 32, owcrypt.HASH_ALG_BLAKE2B), 32, sig, owcrypt.ECC_CURVE_ED25519) {
		return false, ""
	}

	trans = append(trans, byte(0x40))
	trans = append(trans, sig...)

	return true, hex.EncodeToString(trans)
}