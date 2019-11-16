package rippleTransaction

import (
	"encoding/hex"
	"errors"
	"strings"

	owcrypt "github.com/blocktree/go-owcrypt"
)

func CreateEmptyRawTransactionAndHash(from, pubkey string, destinationTag, sequence uint32, to string, amount, fee uint64, lastLedgerSequence uint32, memoType, memoData, memoFormat string) (string, string, error) {
	tx, err := NewTxStruct(from, pubkey,sequence , to, amount, fee, "",destinationTag, lastLedgerSequence, memoType, memoData, memoFormat)
	if err != nil {
		return "", "", err
	}
	return tx.ToEmptyRawWiths(), hex.EncodeToString(tx.GetHash()), nil
}

func SignRawTransaction(hash string, prikey []byte) (string, error) {
	hashBytes, err := hex.DecodeString(hash)
	if err != nil {
		return "", errors.New("Invalid transaction hash string!")
	}
	signature, reCode := owcrypt.Signature(prikey, nil, 0, hashBytes, 32, owcrypt.ECC_CURVE_SECP256K1)
	if reCode != owcrypt.SUCCESS {
		return "", errors.New("failed to sign transaction hash!")
	}
	return hex.EncodeToString(serilizeS(signature)), nil
}

func VerifyAndCombinRawTransaction(emptyTrans string, signature, publicKey string) (bool, string) {
	hash, err := getHashFromEmptyRawHex(emptyTrans)
	if err != nil {
		return false, ""
	}
	pubkeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return false, ""
	}
	sigBytes, err := hex.DecodeString(signature)
	if err != nil {
		return false, ""
	}
	pubkeyBytes = owcrypt.PointDecompress(pubkeyBytes, owcrypt.ECC_CURVE_SECP256K1)[1:]
	if owcrypt.SUCCESS != owcrypt.Verify(pubkeyBytes, nil, 0, hash, 32, sigBytes, owcrypt.ECC_CURVE_SECP256K1) {
		return false, ""
	}
	txnSignature, _ := getTxnSignatureBytes(signature)
	return true, strings.Replace(emptyTrans, "s", hex.EncodeToString(txnSignature), -1)
}
