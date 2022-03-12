package ontologyTransaction

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/blocktree/go-owcrypt"
)

type TxState struct {
	AssetType int // 'ont' or 'ong'
	Payer     string
	From      string
	To        string
	Amount    uint64
}

type TxStateV2 struct {
	AssetType int // 'ont' or 'ong'
	Payer     string
	From      string
	To        string
	Amount    *big.Int
}

func CreateRawTransactionAndHash(gasPrice, gasLimit uint64, txState TxState) (string, *TxHash, error) {
	var th TxHash
	if txState.Payer == "" {
		txState.Payer = txState.From
	}
	payLoad, err := NewNativeInvoke(txState).ToBytes()
	if err != nil {
		return "", nil, err
	}
	randNounce := make([]byte, 4)
	_, err = rand.Read(randNounce[:])

	txBytes, err := NewEmptyTransaction(txState.AssetType, TxTypeInvoke, littleEndianBytesToUint32(randNounce), gasPrice, gasLimit, txState.Payer, payLoad).ToBytes()
	if err != nil {
		return "", nil, err
	}

	th.Hash = hex.EncodeToString(owcrypt.Hash(owcrypt.Hash(txBytes[:len(txBytes)-1], 0, owcrypt.HASH_ALG_DOUBLE_SHA256), 0, owcrypt.HASH_ALG_SHA256))
	th.Addresses = append(th.Addresses, txState.Payer)
	if txState.Payer != txState.From {
		th.Addresses = append(th.Addresses, txState.From)
	}

	return hex.EncodeToString(txBytes), &th, nil
}

func CreateRawTransactionAndHashV2(gasPrice, gasLimit uint64, txState TxStateV2) (string, *TxHash, error) {
	var th TxHash
	if txState.Payer == "" {
		txState.Payer = txState.From
	}
	payLoad, err := NewNativeInvokeV2(txState).ToBytes()
	if err != nil {
		return "", nil, err
	}
	randNounce := make([]byte, 4)
	_, err = rand.Read(randNounce[:])

	txBytes, err := NewEmptyTransaction(txState.AssetType, TxTypeInvoke, littleEndianBytesToUint32(randNounce), gasPrice, gasLimit, txState.Payer, payLoad).ToBytes()
	if err != nil {
		return "", nil, err
	}

	th.Hash = hex.EncodeToString(owcrypt.Hash(owcrypt.Hash(txBytes[:len(txBytes)-1], 0, owcrypt.HASH_ALG_DOUBLE_SHA256), 0, owcrypt.HASH_ALG_SHA256))
	th.Addresses = append(th.Addresses, txState.Payer)
	if txState.Payer != txState.From {
		th.Addresses = append(th.Addresses, txState.From)
	}

	return hex.EncodeToString(txBytes), &th, nil
}

func SignRawTransactionHash(txHash string, prikey []byte) (*SigPub, error) {
	hash, err := hex.DecodeString(txHash)
	if err != nil {
		return nil, errors.New("Invalid transaction hash!")
	}
	return calcSignaturePubkey(hash, prikey)
}

func VerifyAndCombineRawTransaction(emptyTrans string, sigpub []SigPub) (bool, string, error) {
	var sigData SigData
	txBytes, err := hex.DecodeString(emptyTrans)
	if err != nil {
		return false, "", errors.New("Invalid transaction hex data!")
	}
	tx, err := DecodeRawTransaction(txBytes)
	if err != nil {
		return false, "", err
	}

	hashBytes := owcrypt.Hash(owcrypt.Hash(txBytes[:len(txBytes)-1], 0, owcrypt.HASH_ALG_DOUBLE_SHA256), 0, owcrypt.HASH_ALG_SHA256)
	sigData.Nrequired = 0
	for _, sp := range sigpub {
		pubkey := owcrypt.PointDecompress(sp.PublicKey, owcrypt.ECC_CURVE_SECP256R1)[1:]
		if owcrypt.SUCCESS != owcrypt.Verify(pubkey, nil, hashBytes, sp.Signature, owcrypt.ECC_CURVE_SECP256R1) {
			return false, "", errors.New("failed to verify transaction!")
		}
		sigData.SigPubs = append(sigData.SigPubs, sp)
	}
	tx.SigDatas = append(tx.SigDatas, sigData)

	signedTx, err := tx.ToBytes()
	return true, hex.EncodeToString(signedTx), nil
}
