package aliencoinTransaction

import (
	"encoding/hex"
	"errors"

	owcrypt "github.com/blocktree/go-owcrypt"
)

type Vin struct {
	TxID       string
	Vout       uint32
	LockScript string
}

type Vout struct {
	Address string
	Amount  uint64
}

func CreateEmptyTransactionAndHash(vin []Vin, vout []Vout, lockTime uint32) (string, []string, error) {
	txStruct, err := NewTxStruct(vin, vout, lockTime)
	if err != nil {
		return "", nil, err
	}

	hashes, _ := txStruct.GetHash()

	txHex := hex.EncodeToString(txStruct.ToBytes())
	for _, in := range vin {
		txHex += ":" + in.LockScript
	}

	return txHex, hashes, nil
}

func SignTransaction(hash string, prikey []byte) ([]byte, error) {
	hashBytes, err := hex.DecodeString(hash)
	if err != nil {
		return nil, errors.New("Invalid hash!")
	}

	signature, retCode := owcrypt.Signature(prikey, nil, 0, hashBytes, 32, owcrypt.ECC_CURVE_SECP256K1)
	if retCode != owcrypt.SUCCESS {
		return nil, errors.New("Sign Failed!")
	}
	signature = serilizeS(signature)
	return signature, nil
}

func VerifyAndCombineTransaction(emptyTrans string, sigPubs []SigPub) (bool, string, error) {

	txStruct, _, err := DecodeTxStructRaw(emptyTrans)
	if err != nil {
		return false, "", err
	}
	if sigPubs == nil || len(sigPubs) == 0 || len(sigPubs) != len(txStruct.Vin) {
		return false, "", errors.New("inputs and signatures not match!")
	}

	hashes, err := txStruct.GetHash()
	if err != nil {
		return false, "", err
	}
	for index := 0; index < len(sigPubs); index++ {
		hashBytes, _ := hex.DecodeString(hashes[index])
		pubkey := owcrypt.PointDecompress(sigPubs[index].Pubkey, owcrypt.ECC_CURVE_SECP256K1)[1:]
		if owcrypt.SUCCESS != owcrypt.Verify(pubkey, nil, 0, hashBytes, 32, sigPubs[index].Signature, owcrypt.ECC_CURVE_SECP256K1) {
			return false, "", errors.New("verify transaction failed!")
		}
		txStruct.Vin[index].SigPub = &sigPubs[index]
	}

	return true, hex.EncodeToString(txStruct.ToBytes()), nil
}
