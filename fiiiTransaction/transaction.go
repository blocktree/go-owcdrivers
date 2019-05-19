package fiiiTransaction

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	owcrypt "github.com/blocktree/go-owcrypt"
)

type Vin struct {
	TxID string
	Vout int
}

type Vout struct {
	AddressPrefix []byte
	Address       string
	Amount        int64
}

func CreateEmptyTransactionAndMessage(inputs []Vin, outputs []Vout, version int, locktime, expiredtime int64) (string, []string, error) {

	if inputs == nil || len(inputs) == 0 {
		return "", nil, errors.New("No inputs!")
	}
	if outputs == nil || len(outputs) == 0 {
		return "", nil, errors.New("No outputs!")
	}

	txMsg := TransactionMsg{}

	txMsg.Version = version
	txMsg.Timestamp = time.Now().Unix()
	txMsg.LockTime = locktime
	txMsg.ExpiredTime = expiredtime
	txMsg.InputCount = len(inputs)
	txMsg.OutputCount = len(outputs)

	msg := []string{}

	for _, in := range inputs {
		inputMsg, err := in.NewInputMsg()
		if err != nil {
			return "", nil, err
		}
		txMsg.Inputs = append(txMsg.Inputs, *inputMsg)
		msg = append(msg, in.genMessage())
	}

	for i, out := range outputs {
		outputMsg, err := out.NewOutputMsg(i)
		if err != nil {
			return "", nil, err
		}
		txMsg.Outputs = append(txMsg.Outputs, *outputMsg)
	}
	txBytes, err := json.Marshal(txMsg)
	if err != nil {
		return "", nil, errors.New("Failed to serialize transaction message!")
	}
	return string(txBytes), msg, nil
}

func SignTransactionMessage(message string, prikey []byte) ([]byte, error) {

	if len(message) == 0 {
		return nil, errors.New("No message to sign!")
	}

	if prikey == nil || len(prikey) != 32 {
		return nil, errors.New("Invalid private key!")
	}

	data, err := hex.DecodeString(message)
	if err != nil {
		return nil, errors.New("Invalid message to sign!")
	}
	signature, retCode := owcrypt.Signature(prikey, nil, 0, data, uint16(len(data)), owcrypt.ECC_CURVE_ED25519)

	if retCode != owcrypt.SUCCESS {
		return nil, errors.New("Failed to sign message!")
	}

	return signature, nil
}

func VerifyAndCombineTransaction(emptyTrans string, sigPub []SigPub) (bool, string, error) {
	txMsg := TransactionMsg{}

	err := json.Unmarshal([]byte(emptyTrans), &txMsg)

	if err != nil {
		return false, "", errors.New("Invalid empty transaction data!")
	}

	if sigPub == nil || len(sigPub) == 0 || len(sigPub) != len(txMsg.Inputs) {
		return false, "", errors.New("Signatures are not enough to unlock transaction!")
	}

	for i := 0; i < len(sigPub); i++ {
		msg, err := txMsg.Inputs[i].genMessageBytes()
		if err != nil {
			return false, "", err
		}

		fmt.Println("msg:", hex.EncodeToString(msg))
		fmt.Println("sig:", hex.EncodeToString(sigPub[i].Signature))
		fmt.Println("pub:", hex.EncodeToString(sigPub[i].Pubkey))
		if owcrypt.SUCCESS != owcrypt.Verify(sigPub[i].Pubkey, nil, 0, msg, uint16(len(msg)), sigPub[i].Signature, owcrypt.ECC_CURVE_ED25519) {
			return false, "", errors.New("Signature verify failed!")
		}
		unlock, err := sigPub[i].GenUnlockScript()
		if err != nil {
			return false, "", err
		}
		txMsg.Inputs[i].UnlockScript = unlock
		txMsg.Inputs[i].Size = len(unlock)
	}

	txMsg.Complete()
	txBytes, err := json.Marshal(txMsg)
	if err != nil {
		return false, "", errors.New("Failed to marshal transaction!")
	}

	return true, string(txBytes), nil
}
