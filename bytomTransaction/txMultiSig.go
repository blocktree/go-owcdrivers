package bytomTransaction

import (
	"encoding/hex"
	"errors"

	"github.com/blocktree/go-owcrypt"
)

func CreateMultiSig(required byte, pubkeys [][]byte) (string, string, error) {
	if pubkeys == nil || len(pubkeys) == 0 {
		return "", "", errors.New("No pubkeys input!")
	}

	if required <= 0 {
		return "", "", errors.New("Required number should be at least one!")
	}

	if len(pubkeys) < int(required) {
		return "", "", errors.New("The required number is bigger than the count of pubkeys!")
	}

	signScript := []byte{}

	signScript = append(signScript, Op_TxSignHash)

	for _, key := range pubkeys {
		if key == nil || len(key) != 0x20 {
			return "", "", errors.New("Invalid pubkey data for create multisig!")
		}
		signScript = append(signScript, 0x20)
		signScript = append(signScript, key...)
	}

	signScript = append(signScript, Op_1-1+required)
	signScript = append(signScript, Op_1-1+byte(len(pubkeys)))
	signScript = append(signScript, Op_CheckMultiSig)

	scriptHash := owcrypt.Hash(signScript, 0, owcrypt.HASH_ALG_SHA3_256)

	address, err := encodeSegWitAddress(Bech32HRPSegwit, DefaultWitnessVersion, scriptHash)

	if err != nil {
		return "", "", err
	}

	return address, hex.EncodeToString(signScript), nil
}

func getMultiSigDetail(signScript []byte) ([]MultiTx, byte, error) {
	limit := len(signScript)
	index := 0

	if index+1 > limit {
		return nil, 0, errors.New("Invalid signScript data!")
	}

	if signScript[index] != Op_TxSignHash {
		return nil, 0, errors.New("Invalid signScript data!")
	}
	index++

	var multi []MultiTx

	for {
		if index+1 > limit {
			return nil, 0, errors.New("Invalid signScript data!")
		}

		if signScript[index] != 0x20 {
			break
		}
		index++

		if index+0x20 > limit {
			return nil, 0, errors.New("Invalid signScript data!")
		}
		multi = append(multi, MultiTx{hex.EncodeToString(signScript[index : index+0x20]), SigPub{}})
		index += 0x20
	}

	required := signScript[index] - (Op_1 - 1)

	if required <= 0 {
		return nil, 0, errors.New("Invalid required number for a multi sigScript!")
	}
	index++

	if index+1 > limit {
		return nil, 0, errors.New("Invalid signScript data!")
	}
	if signScript[index]-(Op_1-1) != byte(len(multi)) {
		return nil, 0, errors.New("Invalid signScript data!")
	}
	index++
	if index+1 > limit {
		return nil, 0, errors.New("Invalid signScript data!")
	}
	if signScript[index] != Op_CheckMultiSig {
		return nil, 0, errors.New("Invalid signScript data!")
	}
	index++
	if index != limit {
		return nil, 0, errors.New("Invalid signScript data!")
	}

	return multi, required, nil
}

func getMultiSigPubs(sp []byte) ([][]byte, [][]byte, error) {

	var sigs [][]byte
	var pubs [][]byte

	limit := len(sp)
	index := 0

	if index+2 > limit {
		return nil, nil, errors.New("Invalid signature and public key data!")
	}

	if sp[index] != 0x01 || sp[index+1] != 0x03 {
		return nil, nil, errors.New("Invalid signature and public key data!")
	}

	index += 2

	for {
		if index+1 > limit {
			return nil, nil, errors.New("Invalid signature and public key data!")
		}

		if sp[index] == 0x40 {
			index++
			if index+0x40 > limit {
				return nil, nil, errors.New("Invalid signature and public key data!")
			}
			sigs = append(sigs, sp[index:index+0x40])
			index += 0x40
		} else {
			break
		}
	}

	if index+1 > limit {
		return nil, nil, errors.New("Invalid signature and public key data!")
	}

	commitLen := int(sp[index])

	index++

	if index+commitLen != limit {
		return nil, nil, errors.New("Invalid signature and public key data!")
	}
	if index+1 > limit {
		return nil, nil, errors.New("Invalid signature and public key data!")
	}
	if sp[index] != Op_TxSignHash {
		return nil, nil, errors.New("Invalid signature and public key data!")
	}
	index++
	for {
		if index+1 > limit {
			return nil, nil, errors.New("Invalid signature and public key data!")
		}
		if sp[index] != 0x20 {
			break
		}
		index++

		if index+0x20 > limit {
			return nil, nil, errors.New("Invalid signature and public key data!")
		}

		pubs = append(pubs, sp[index:index+0x20])

		index += 0x20
	}

	required := sp[index] - (Op_1 - 1)
	index++

	if index+1 > limit {
		return nil, nil, errors.New("Invalid signature and public key data!")
	}

	count := sp[index] - (Op_1 - 1)
	index++

	if int(count) != len(pubs) {
		return nil, nil, errors.New("Invalid signature and public key data!")
	}

	if int(required) != len(sigs) {
		return nil, nil, errors.New("Not competely signed!")
	}
	if index+1 > limit {
		return nil, nil, errors.New("Invalid signature and public key data!")
	}

	if sp[index] != Op_CheckMultiSig {
		return nil, nil, errors.New("Invalid signature and public key data!")
	}
	index++

	if index != limit {
		return nil, nil, errors.New("Invalid signature and public key data!")
	}

	return sigs, pubs, nil
}
