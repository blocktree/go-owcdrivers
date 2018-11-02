package bytomTransaction

import (
	"encoding/hex"
	"errors"

	"github.com/blocktree/go-owcrypt"
)

type NormalTx struct {
	Address string
	SigPub  SigPub
}

type MultiTx struct {
	Pubkey string
	SigPub SigPub
}

type TxHash struct {
	Hash      string
	NRequired byte
	Normal    *NormalTx
	Multi     []MultiTx
}

func (th TxHash) IsMultiSig() bool {
	return th.NRequired != 0
}

func (th *TxHash) PadMultiSig(signScriptHex string) error {
	signScript, err := hex.DecodeString(signScriptHex)
	if err != nil {
		return errors.New("Invalid signScript hex string!")
	}

	multi, required, err := getMultiSigDetail(signScript)
	if err != nil {
		return err
	}

	th.NRequired = required
	th.Multi = multi
	return nil
}

func (th TxHash) getMultiSigBytes() ([]byte, []byte, error) {
	if !th.IsMultiSig() {
		return nil, nil, errors.New("Not a multisig txhash!")
	}

	signScript := []byte{}

	signScript = append(signScript, Op_TxSignHash)

	for _, key := range th.Multi {
		if key.SigPub.Pubkey == nil || len(key.SigPub.Pubkey) != 0x20 {
			return nil, nil, errors.New("Invalid pubkey data for create multisig!")
		}
		signScript = append(signScript, 0x20)
		signScript = append(signScript, key.SigPub.Pubkey...)
	}

	signScript = append(signScript, Op_1-1+th.NRequired)
	signScript = append(signScript, Op_1-1+byte(len(th.Multi)))
	signScript = append(signScript, Op_CheckMultiSig)

	scriptHash := owcrypt.Hash(signScript, 0, owcrypt.HASH_ALG_SHA3_256)

	scriptHash = append([]byte{0x00, 0x20}, scriptHash...)

	sigBytes := []byte{}

	sigBytes = append(sigBytes, 0x01, 0x03)

	count := 0
	for _, sp := range th.Multi {
		if sp.SigPub.Signature == nil {
			continue
		}
		if len(sp.SigPub.Signature) != 0x40 {
			return nil, nil, errors.New("Invalid length of signature!")
		}

		sigBytes = append(sigBytes, 0x40)
		sigBytes = append(sigBytes, sp.SigPub.Signature...)
		count++

		if byte(count) == th.NRequired {
			break
		}
	}

	if byte(count) < th.NRequired {
		return nil, nil, errors.New("Not competely signed!")
	}

	sigBytes = append(sigBytes, byte(len(signScript)))
	sigBytes = append(sigBytes, signScript...)

	sigBytes = append([]byte{byte(len(sigBytes) - 1)}, sigBytes...)
	return sigBytes, scriptHash, nil
}
