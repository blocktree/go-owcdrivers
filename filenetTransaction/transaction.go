package filenetTransaction

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/blocktree/go-owcrypt"
)

type Vin struct {
	Address string
}

type Vout struct {
	Address string
	Amount uint64
}

type Vouts []Vout

func CreateEmptyTransactionAndHash(in Vin, outs Vouts) (string, string, error) {

	tx, err := NewTxStruct(in, outs)
	if err != nil {
		return "", "", err
	}

	txBytes := tx.ToBytes()

	hash := owcrypt.Hash(txBytes, 0, owcrypt.HASH_ALG_SHA256)


	return hex.EncodeToString(txBytes), hex.EncodeToString(hash), nil
}

func SignTransaction(hash string, prikey []byte) (string, error) {
	if hash == "" || prikey == nil || len(prikey) != 32 {
		return "", errors.New("Invalid input data!")
	}

	hashBytes, err := hex.DecodeString(hash)
	if err != nil || len(hashBytes) != 32 {
		return "", errors.New("Invalid hash data!")
	}

	signature,_, retCode := owcrypt.Signature(prikey, nil, hashBytes, owcrypt.ECC_CURVE_SECP256K1)
	if retCode != owcrypt.SUCCESS {
		return "", errors.New("Failed to sign transaction!")
	}

	return hex.EncodeToString(signature), nil
}

func VerifyAndCombineTransaction(emptyTrans, signature, pubkey  string) (string, bool) {

	tx, err := decodeRawTransaction(emptyTrans, signature)
	if err != nil {
		return "", false
	}

	hash, _ := hex.DecodeString(tx.TxId)
	sig, _ := hex.DecodeString(signature)

	pubBytes, err := hex.DecodeString(pubkey)
	if err != nil {
		return "", false
	}

	pubBytes = owcrypt.PointDecompress(pubBytes, owcrypt.ECC_CURVE_SECP256K1)[1:]

	if owcrypt.SUCCESS != owcrypt.Verify(pubBytes, nil, hash, sig, owcrypt.ECC_CURVE_SECP256K1) {
		return "", false
	}

	data, err := json.Marshal(tx)

	if err != nil {
		return "", false
	}
	return string(data), true
}