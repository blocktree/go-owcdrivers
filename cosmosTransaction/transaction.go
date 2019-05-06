package cosmosTransaction

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"

	owcrypt "github.com/blocktree/go-owcrypt"
	"github.com/tidwall/gjson"
)

func (tx TxStruct) CreateEmptyTransactionAndHash() (string, string, error) {

	txBytes, err := json.Marshal(tx)
	if err != nil {
		return "", "", errors.New("CreateEmptyTransaction failed!")
	}

	hash := owcrypt.Hash(txBytes, 0, owcrypt.HASH_ALG_SHA256)

	return string(txBytes), hex.EncodeToString(hash), nil
}

var (
	CurveOrder     = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41}
	HalfCurveOrder = []byte{0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0}
)

func serilizeS(sig []byte) []byte {
	s := sig[32:]
	numS := new(big.Int).SetBytes(s)
	numHalfOrder := new(big.Int).SetBytes(HalfCurveOrder)
	if numS.Cmp(numHalfOrder) > 0 {
		numOrder := new(big.Int).SetBytes(CurveOrder)
		numS.Sub(numOrder, numS)

		s = numS.Bytes()
		if len(s) < 32 {
			for i := 0; i < 32-len(s); i++ {
				s = append([]byte{0x00}, s...)
			}
		}
		return append(sig[:32], s...)
	}
	return sig
}

func SignTransactionHash(txHash string, prikey []byte) (string, error) {
	hash, err := hex.DecodeString(txHash)
	if err != nil {
		return "", errors.New("Invalid transaction hash!")
	}
	if len(hash) != 32 || prikey == nil || len(prikey) != 32 {
		return "", errors.New("Invalid transaction hash!")
	}

	sig, ret := owcrypt.Signature(prikey, nil, 0, hash, 32, owcrypt.ECC_CURVE_SECP256K1)

	if ret != owcrypt.SUCCESS {
		return "", errors.New("Signature failed!")
	}

	return hex.EncodeToString(sig), nil
}

func VerifyTransactionSig(emptyTrans, signature string, pubkey []byte) bool {
	txBytes := []byte(emptyTrans)
	hash := owcrypt.Hash(txBytes, 0, owcrypt.HASH_ALG_SHA256)

	sig, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	if owcrypt.Verify(pubkey, nil, 0, hash, 32, sig, owcrypt.ECC_CURVE_SECP256K1) != owcrypt.SUCCESS {
		return false
	}

	return true
}

func (ts TxStruct) CreateJsonForSend(signature string, pubkey []byte, keyType, sendMode string) (*gjson.Result, error) {
	pub := NewPub(pubkey, keyType)
	sigBytes, err := hex.DecodeString(signature)
	if err != nil {
		return nil, errors.New("create json fro send failed!")
	}
	sig := NewSig(sigBytes, ts.AccountNumber, ts.Sequence, pub)

	tx := NewTx(ts.Message, ts.Memo, ts.Fee, sig)

	txSend := NewTxSend(tx, sendMode)

	json, _ := json.Marshal(txSend)
	ret := gjson.ParseBytes(json)

	return &ret, nil
}
