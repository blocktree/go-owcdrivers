package bytomTransaction

import (
	"encoding/hex"
	"errors"

	"github.com/blocktree/go-owcrypt"
)

type Vin struct {
	SourceID       string
	SourcePosition uint64
	AssetID        string
	Amount         uint64
	ControlProgram string
}

type Vout struct {
	Address string
	Amount  uint64
}

func CreateEmptyRawTransaction(vins []Vin, vouts []Vout, timeRange uint64) (string, error) {
	emptyTrans, err := newEmptyTransaction(vins, vouts, timeRange)
	if err != nil {
		return "", err
	}

	txBytes, err := emptyTrans.toBytes()
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(txBytes), nil
}

func CreateRawTransactionHashForSig(txHex string) ([]TxHash, error) {
	txBytes, err := hex.DecodeString(txHex)
	if err != nil {
		return nil, errors.New("Invalid transaction hex string!")
	}

	emptyTrans, err := DecodeRawTransaction(txBytes)

	if err != nil {
		return nil, err
	}
	var ret []TxHash
	for i := 0; i < len(emptyTrans.Inputs); i++ {
		var tH TxHash
		hashBytes, err := emptyTrans.getSigHash(i)
		if err != nil {
			return nil, err
		}

		tH.Hash = hex.EncodeToString(hashBytes)
		if len(emptyTrans.Inputs[i].ControlProgram) == 34 {
			tH.NRequired = 1
		} else {
			addr, err := encodeSegWitAddress(Bech32HRPSegwit, DefaultWitnessVersion, emptyTrans.Inputs[i].ControlProgram[2:])

			if err != nil {
				return nil, err
			}
			tH.Normal = &NormalTx{addr, SigPub{}}
		}

		ret = append(ret, tH)
	}

	return ret, nil
}

func SignRawTransactionHash(txHash string, prikey []byte) (*SigPub, error) {
	hash, err := hex.DecodeString(txHash)
	if err != nil {
		return nil, errors.New("Invalid transaction hash!")
	}

	return calcSignaturePubkey(hash, prikey)
}

func InsertSignatureIntoEmptyTransaction(txHex string, txHashes []TxHash) (string, error) {
	txBytes, err := hex.DecodeString(txHex)
	if err != nil {
		return "", errors.New("Invalid transaction hex string!")
	}

	emptyTrans, err := DecodeRawTransaction(txBytes)

	if err != nil {
		return "", err
	}

	if txHashes == nil || len(txHashes) == 0 {
		return "", errors.New("No signature data found!")
	}

	if emptyTrans.Inputs == nil || len(emptyTrans.Inputs) == 0 {
		return "", errors.New("Invalid empty transaction,no input found!")
	}

	if emptyTrans.Outputs == nil || len(emptyTrans.Outputs) == 0 {
		return "", errors.New("Invalid empty transaction,no output found!")
	}

	for i := 0; i < len(txHashes); i++ {
		if txHashes[i].IsMultiSig() {
			multiSigData, controlProgram, err := txHashes[i].getMultiSigBytes()
			if err != nil {
				return "", err
			}
			emptyTrans.Inputs[i].ControlProgram = controlProgram
			emptyTrans.Inputs[i].MultiSig = multiSigData
			emptyTrans.Inputs[i].SigPub = nil
		} else {
			emptyTrans.Inputs[i].SigPub = &txHashes[i].Normal.SigPub
			emptyTrans.Inputs[i].MultiSig = nil
		}

	}
	signTx, err := (*emptyTrans).toBytes()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(signTx), nil
}

func VerifyRawTransaction(txHex string) bool {

	txBytes, err := hex.DecodeString(txHex)

	if err != nil {
		return false
	}

	signedTrans, err := DecodeRawTransaction(txBytes)

	if err != nil {
		return false
	}

	if signedTrans.Inputs == nil || len(signedTrans.Inputs) == 0 {
		return false
	}

	emptyTrans := signedTrans.cloneEmpty()

	var txHashes [][]byte

	for i := 0; i < len(emptyTrans.Inputs); i++ {
		hash, err := emptyTrans.getSigHash(i)
		if err != nil {
			return false
		}
		txHashes = append(txHashes, hash)
	}

	for i := 0; i < len(txHashes); i++ {
		if owcrypt.SUCCESS != owcrypt.Verify(signedTrans.Inputs[i].SigPub.Pubkey, nil, 0, txHashes[i], 32, signedTrans.Inputs[i].SigPub.Signature, owcrypt.ECC_CURVE_ED25519) {
			return false
		}
	}
	return true
}
