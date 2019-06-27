package waykichainTransaction

import (
	"encoding/hex"
	"errors"

	owcrypt "github.com/blocktree/go-owcrypt"
)

// fromUserID - user id when txType is TxType_COMMON
// fromUserID - publick key hex when txType is TxType_REGACCT
// to - contract Hex when txType is TxType_CONTRACT
func CreateEmptyRawTransactionAndHash(fromUserID, to, appID string, amount, fee, validHeight int64, txType byte) (string, string, error) {
	if txType == TxType_COMMON {
		txCommon, err := NewCommonTx(fromUserID, to, amount, fee, validHeight)
		if err != nil {
			return "", "", err
		}
		return hex.EncodeToString(txCommon.ToBytes()), hex.EncodeToString(txCommon.GetHash()), nil
	} else if txType == TxType_REGACCT {
		txRegisterAccount, err := NewRegisterAccountTx(fromUserID, fee, validHeight)
		if err != nil {
			return "", "", err
		}

		return hex.EncodeToString(txRegisterAccount.ToBytes()), hex.EncodeToString(txRegisterAccount.GetHash()), nil
	} else if txType == TxType_CONTRACT {
		txContract, err := NewCallContractTx(fromUserID, appID, to, validHeight, fee, amount)
		if err != nil {
			return "", "", err
		}

		return hex.EncodeToString(txContract.ToBytes()), hex.EncodeToString(txContract.GetHash()), nil
	}
	return "", "", errors.New("Unknown transaction type")
}

func SignRawTransaction(hash string, prikey []byte) ([]byte, error) {
	hashBytes, err := hex.DecodeString(hash)
	if err != nil {
		return nil, errors.New("Invalid transaction hash string!")
	}

	signature, retCode := owcrypt.Signature(prikey, nil, 0, hashBytes, 32, owcrypt.ECC_CURVE_SECP256K1)
	if retCode != owcrypt.SUCCESS {
		return nil, errors.New("Failed to sign transaction hash!")
	}

	return signature, nil
}

func VerifyAndCombineRawTransaction(emptyTrans string, sigPub SigPub) (bool, string) {
	hash, err := getHashFromEmptyRawTrans(emptyTrans)
	if err != nil {
		return false, ""
	}
	pubkey := owcrypt.PointDecompress(sigPub.PublicKey, owcrypt.ECC_CURVE_SECP256K1)[1:]

	if owcrypt.SUCCESS != owcrypt.Verify(pubkey, nil, 0, hash, 32, sigPub.Signature, owcrypt.ECC_CURVE_SECP256K1) {
		return false, ""
	}

	return true, emptyTrans + hex.EncodeToString(sigPub.ToBytes())
}
