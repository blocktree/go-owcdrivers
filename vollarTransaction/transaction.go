package vollarTransaction

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

func CreateEmptyRawTransactionAndHash(vins []Vin, vouts []Vout) (string, []string, error) {

	txStruct, err := NewTxStruct(vins, vouts)
	if err != nil {
		return "", nil, err
	}

	hashes, err := txStruct.GetHash()
	if err != nil {
		return "", nil, err
	}
	return hex.EncodeToString(txStruct.ToBytes()), hashes, nil
}

func SignRawTransaction(hash string, prikey []byte) ([]byte, error) {
	hashBytes, err := hex.DecodeString(hash)
	if err != nil {
		return nil, errors.New("invalid hash message")
	}
	sig, retCode := owcrypt.Signature(prikey, nil, 0, hashBytes, 32, owcrypt.ECC_CURVE_SECP256K1)

	if retCode != owcrypt.SUCCESS {
		return nil, errors.New("sign failed!")
	}

	return sig, nil
}

func VerifyAndCombineRawTransaction(emptyTrans string, sigPub []SigPub, lockScripts []string) (bool, string, error) {
	trans, err := DecodeTxStructRaw(emptyTrans)
	if err != nil {
		return false, "", err
	}

	if len(trans.Vin) != len(sigPub) || len(trans.Vin) != len(lockScripts) {
		return false, "", errors.New("signature and inputs are dismatched!")
	}
	for index := 0; index < len(lockScripts); index++ {
		ls, err := hex.DecodeString(lockScripts[index])
		if err != nil {
			return false, "", errors.New("invalid lock script!")
		}
		trans.Vin[index].LockScript = append([]byte{byte(len(ls))}, ls...)
	}

	hashes, err := trans.GetHash()
	if err != nil {
		return false, "", err
	}

	pass := true

	for i := 0; i < len(sigPub); i++ {
		hash, _ := hex.DecodeString(hashes[i])
		pubkey := owcrypt.PointDecompress(sigPub[i].Pubkey, owcrypt.ECC_CURVE_SECP256K1)[1:]
		if owcrypt.SUCCESS != owcrypt.Verify(pubkey, nil, 0, hash, 32, sigPub[i].Signature, owcrypt.ECC_CURVE_SECP256K1) {
			pass = false
		}
		trans.Vin[i].SigPub = &sigPub[i]
	}

	txBytes := trans.ToBytes()
	for index := 0; index < 83; index++ {
		txBytes = append(txBytes, byte(0))
	}
	return pass, hex.EncodeToString(txBytes), nil
}
