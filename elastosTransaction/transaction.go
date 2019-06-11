package elastosTransaction

import (
	"encoding/hex"
	"errors"

	owcrypt "github.com/blocktree/go-owcrypt"
)

type Vin struct {
	TxID    string
	Vout    uint16
	Address string
}

type Vout struct {
	AssetID string
	Amount  uint64
	Address string
}

type TxHash struct {
	Address string
	Hash    string
}

func CreateEmptyRawTransactionAndHash(vins []Vin, vouts []Vout) (string, []TxHash, error) {
	if vins == nil || len(vins) == 0 || vouts == nil || len(vouts) == 0 {
		return "", nil, errors.New("Miss inputs or outputs!")
	}
	tx, err := NewTransaction(vins, vouts)
	if err != nil {
		return "", nil, err
	}
	emptyTrans, hash := tx.GetEmptyAndHash()

	txHashes := []TxHash{}

loop:
	for _, in := range vins {
		for _, txHash := range txHashes {
			if txHash.Address == in.Address {
				continue loop
			}
		}
		txHashes = append(txHashes, TxHash{Address: in.Address, Hash: hex.EncodeToString(hash)})

	}

	return hex.EncodeToString(emptyTrans), txHashes, nil
}

func SignRawTransaction(hash string, privateKey []byte) ([]byte, error) {
	hashByte, err := hex.DecodeString(hash)
	if err != nil {
		return nil, errors.New("Invalid transaction hash!")
	}

	signature, retCode := owcrypt.Signature(privateKey, nil, 0, hashByte, 32, owcrypt.ECC_CURVE_SECP256R1)
	if retCode != owcrypt.SUCCESS {
		return nil, errors.New("Failed to sign transaction!")
	}

	return signature, nil
}

func VerifyAndCombineRawTransaction(emptyTrans string, sigPubs []SigPub) (bool, string) {

	txBytes, err := hex.DecodeString(emptyTrans)
	if err != nil {
		return false, ""
	}

	hash := owcrypt.Hash(txBytes, 0, owcrypt.HASH_ALG_SHA256)

	for _, sp := range sigPubs {
		publicKey := owcrypt.PointDecompress(sp.PublicKey, owcrypt.ECC_CURVE_SECP256R1)[1:]
		if owcrypt.SUCCESS != owcrypt.Verify(publicKey, nil, 0, hash, 32, sp.Signature, owcrypt.ECC_CURVE_SECP256R1) {
			return false, ""
		}
	}

	sigRaw, err := Sigpubs(sigPubs).ToBytes()
	if err != nil {
		return false, ""
	}

	return true, hex.EncodeToString(append(txBytes, sigRaw...))
}
