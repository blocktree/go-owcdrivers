package moacchainTransaction

import (
	"encoding/hex"
	"errors"
	"math/big"
	"strings"

	"github.com/blocktree/go-owcdrivers/signatureSet"
	owcrypt "github.com/blocktree/go-owcrypt"
)

func CreateEmptyRawTransactionAndHash(to string, nonce uint64, amount, gasLimit, gasPrice *big.Int, isTestNet bool) (string, string, error) {
	tx, err := NewTxStruct(to, nonce, amount, gasLimit, gasPrice, nil, isTestNet)
	if err != nil {
		return "", "", err
	}
	emptyTrans := tx.ToBytes()
	hash := owcrypt.Hash(emptyTrans, 0, owcrypt.HASH_ALG_KECCAK256)

	return hex.EncodeToString(emptyTrans), hex.EncodeToString(hash), nil
}

func SignRawTransaction(hash string, privateKey []byte) ([]byte, error) {
	hashBytes, err := hex.DecodeString(hash)
	if err != nil || len(hashBytes) != 32 {
		return nil, errors.New("Invalid hash string!")
	}

	signature, retCode := signatureSet.MoacSignature(privateKey, hashBytes)
	if retCode != owcrypt.SUCCESS {
		return nil, errors.New("Failed to sign transaction!")
	}
	return signature, nil
}

func VerifyAndCombineRawTransaction(emptyTrans, signature, publicKey string, isTestNet bool) (bool, string) {
	txBytes, err := hex.DecodeString(emptyTrans)
	if err != nil {
		return false, ""
	}
	hash := owcrypt.Hash(txBytes, 0, owcrypt.HASH_ALG_KECCAK256)
	sig, err := hex.DecodeString(signature)
	if err != nil || len(sig) != 65 || (sig[64] != 0x01) && sig[64] != 0x00 {
		return false, ""
	}
	pub, retCode := owcrypt.RecoverPubkey(sig, hash, owcrypt.ECC_CURVE_SECP256K1)
	if retCode != owcrypt.SUCCESS || strings.ToLower(hex.EncodeToString(owcrypt.PointCompress(pub, owcrypt.ECC_CURVE_SECP256K1))) != strings.ToLower(publicKey) {
		return false, ""
	}
	if owcrypt.SUCCESS != owcrypt.Verify(pub, nil, 0, hash, 32, sig, owcrypt.ECC_CURVE_SECP256K1) {
		return false, ""
	}
	if len(txBytes) < 57 {
		head := getHeadBytes(SmallTag, LargeTag, uint64(len(txBytes)-1))
		if head[0] != txBytes[0] {
			return false, ""
		}
	} else {
		//
	}
	tx, err := decodeEmpty(txBytes[1:])
	if err != nil {
		return false, ""
	}
	tx.addSig(sig, isTestNet)

	return true, "0x" + hex.EncodeToString(tx.ToBytes())
}
