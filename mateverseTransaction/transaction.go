package mateverseTransaction

import (
	"encoding/hex"
	"errors"
	"github.com/blocktree/go-owcrypt"
)

func GetInputsFromEmptyRawTransaction(emptyTrans string) ([]*TxInput, error){
	trans, err := hex.DecodeString(emptyTrans)
	if err != nil {
		return nil, errors.New("Invalid empty raw transaction!")
	}
	inputs, _, err := decodeEmptyTx(trans)
	if err != nil {
		return nil, err
	}

	return inputs, nil
}

func GetSigHash(emptyTrans string, inputs *[]*TxInput) error {

	trans, err := hex.DecodeString(emptyTrans)
	if err != nil {
		return errors.New("Invalid empty raw transaction!")
	}
	_, inputsEnd, err := decodeEmptyTx(trans)
	if err != nil {
		return err
	}

	for i, input := range *inputs {
		if input.lockScript == "" {
			return errors.New("Miss lock script!")
		}
		lockScript := getHashFromLockScript(input.lockScript)
		if lockScript == "" || len(lockScript) != 50 {
			return errors.New("Invalid lock script!")
		}
		input.SetLockScript(lockScript)
		_, err = hex.DecodeString(input.txID)
		if err != nil || len(input.txID) != 64 {
			return errors.New("Invalid txid!")
		}
		hashBytes := getHashCalcBytes(*inputs, i)

		hashBytes = append(hashBytes, trans[inputsEnd:]...)
		hashBytes = append(hashBytes, uint32ToLittleEndianBytes(SigHashAll)...)

		input.hash = hex.EncodeToString(owcrypt.Hash(hashBytes, 0, owcrypt.HASh_ALG_DOUBLE_SHA256))
	}

	return nil
}

func SignTransaction(hash string, prikey []byte) (string, error) {
	hashBytes, err := hex.DecodeString(hash)
	if err != nil || len(hashBytes) != 32 {
		return "", errors.New("Invalid transaction hash!")
	}
	if prikey == nil || len(prikey) != 32 {
		return "", errors.New("Invalid prikey!")
	}

	signature, reCode := owcrypt.Signature(prikey, nil, 0, hashBytes, 32, owcrypt.ECC_CURVE_SECP256K1)
	if reCode != owcrypt.SUCCESS {
		return "", errors.New("Failed to sign transaction!")
	}

	serilizeS(signature)

	return hex.EncodeToString(signature), nil
}

func VerifyAndCombineTransaction(emptyTrans string, inputs []*TxInput) (bool, string) {

	for _, input := range inputs {
		if !verifyTransactionHash(input.pubkey, input.hash, input.signature) {
			return false, ""
		}
	}

	tx := getSubmitBytes(inputs, emptyTrans)

	if tx == nil {
		return false, ""
	}

	return true, hex.EncodeToString(tx)
}