package ontologyTransaction

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/blocktree/go-owcrypt"
)

type TxState struct {
	AssetType int // 'ont' or 'ong'
	From      string
	To        string
	Amount    uint64
}

func CreateEmptyRawTransaction(gasPrice, gasLimit uint64, txState TxState) (string, error) {

	payLoad, err := NewNativeInvoke(txState).ToBytes()
	if err != nil {
		return "", err
	}
	randNounce := make([]byte, 4)
	_, err = rand.Read(randNounce[:])

	txBytes, err := NewEmptyTransaction(txState.AssetType, TxTypeInvoke, littleEndianBytesToUint32(randNounce), gasPrice, gasLimit, txState.From, payLoad).ToBytes()
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(txBytes), nil
}

func CreateRawTransactionHashForSig(txHex string) (*TxHash, error) {
	var ret TxHash
	var normal NormalTx
	txBytes, err := hex.DecodeString(txHex)
	if err != nil {
		return nil, errors.New("Invalid transaction hex data!")
	}
	tx, err := DecodeRawTransaction(txBytes)

	if err != nil {
		return nil, err
	}

	normal.Address = EncodeCheck(AddressPrefix, tx.Payer)
	ret.NRequired = 0
	ret.Hash = hex.EncodeToString(owcrypt.Hash(owcrypt.Hash(txBytes[:len(txBytes)-1], 0, owcrypt.HASh_ALG_DOUBLE_SHA256), 0, owcrypt.HASH_ALG_SHA256))

	ret.Normal = &normal

	return &ret, nil
}

func SignRawTransactionHash(txHash string, prikey []byte) (*SigPub, error) {
	hash, err := hex.DecodeString(txHash)
	if err != nil {
		return nil, errors.New("Invalid transaction hash!")
	}
	return calcSignaturePubkey(hash, prikey)
}

func InsertSignatureIntoEmptyTransaction(txHex string, sp SigPub) (string, error) {
	txBytes, err := hex.DecodeString(txHex)
	if err != nil {
		return "", errors.New("Invalid transaction hex data!")
	}
	tx, err := DecodeRawTransaction(txBytes)

	if err != nil {
		return "", err
	}

	var sigData SigData
	sigData.Nrequired = 0
	sigData.SigPubs = append(sigData.SigPubs, sp)

	tx.SigDatas = append(tx.SigDatas, sigData)

	signedTx, err := tx.ToBytes()

	if err != nil {
		return "", err
	}
	return hex.EncodeToString(signedTx), nil
}

func VerifyRawTransaction(txHex string) bool {
	txBytes, err := hex.DecodeString(txHex)
	if err != nil {
		return false
	}

	tx, err := DecodeRawTransaction(txBytes)
	if err != nil {
		return false
	}

	emptyTx := tx.cloneEmpty()

	emptyTxBytes, err := emptyTx.ToBytes()

	if err != nil {
		return false
	}

	txHash, err := CreateRawTransactionHashForSig(hex.EncodeToString(emptyTxBytes))

	if err != nil {
		return false
	}

	pubkey := owcrypt.PointDecompress(tx.SigDatas[0].SigPubs[0].PublicKey, owcrypt.ECC_CURVE_SECP256R1)[1:]
	hash, _ := hex.DecodeString(txHash.Hash)
	if owcrypt.SUCCESS != owcrypt.Verify(pubkey, nil, 0, hash, 32, tx.SigDatas[0].SigPubs[0].Signature, owcrypt.ECC_CURVE_SECP256R1) {
		fmt.Println("test", hex.EncodeToString(tx.SigDatas[0].SigPubs[0].Signature))
		return false
	}
	return true
}

// 1c389bc95b730f109485de8854421a1d8344c52f33412893dca2b49f99e109cf34c77d1498efda72f3f4317bcd8170a4092245cc4a8f92a9c5133c2df7f4052e
