package zencashTransaction

import (
	"encoding/hex"
	"errors"
	"github.com/blocktree/go-owcrypt"
)

type Vin struct {
	TxID string
	Vout uint32
}

type Vout struct {
	Address string
	Amount  uint64
}

type TxUnlock struct {
	//PrivateKey   []byte
	LockScript   string
	RedeemScript string
	Amount       uint64
	//	Address      string
	SigType byte
}

func CreateEmptyRawTransaction(vins []Vin, vouts []Vout, lockTime uint32, replaceable bool, addressPrefix AddressPrefix, blockHash string, blockHeight uint64) (string, error) {

	emptyTrans, err := newEmptyTransaction(vins, vouts, lockTime, replaceable, addressPrefix, blockHash, blockHeight)
	if err != nil {
		return "", err
	}

	txBytes, err := emptyTrans.encodeToBytes(false)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(txBytes), nil
}

func CreateRawTransactionHashForSig(txHex string, unlockData []TxUnlock, SegwitON bool, addressPrefix AddressPrefix) ([]TxHash, error) {
	txBytes, err := hex.DecodeString(txHex)
	if err != nil {
		return nil, errors.New("Invalid transaction hex string!")
	}

	emptyTrans, err := DecodeRawTransaction(txBytes, SegwitON)
	if err != nil {
		return nil, err
	}

	return emptyTrans.getHashesForSig(unlockData, SegwitON, addressPrefix)
}

func SignRawTransactionHash(txHash string, prikey []byte) (*SignaturePubkey, error) {
	hash, err := hex.DecodeString(txHash)
	if err != nil {
		return nil, errors.New("Invalid transaction hash!")
	}

	return calcSignaturePubkey(hash, prikey)
}

func InsertSignatureIntoEmptyTransaction(txHex string, txHashes []TxHash, unlockData []TxUnlock, SegwitON bool) (string, error) {
	txBytes, err := hex.DecodeString(txHex)
	if err != nil {
		return "", errors.New("Invalid transaction hex data!")
	}

	emptyTrans, err := DecodeRawTransaction(txBytes, SegwitON)
	if err != nil {
		return "", err
	}

	if unlockData == nil || len(unlockData) == 0 {
		return "", errors.New("No unlock data found!")
	}

	if txHashes == nil || len(txHashes) == 0 {
		return "", errors.New("No signature data found!")
	}

	if emptyTrans.Vins == nil || len(emptyTrans.Vins) == 0 {
		return "", errors.New("Invalid empty transaction,no input found!")
	}

	if emptyTrans.Vouts == nil || len(emptyTrans.Vouts) == 0 {
		return "", errors.New("Invalid empty transaction,no output found!")
	}

	if len(emptyTrans.Vins) != len(unlockData) {
		return "", errors.New("The number of transaction inputs and the unlock data are not match!")
	}

	segwit := false

	if segwit && !SegwitON {
		return "", errors.New("Segwit transaction found while SegwitON is set to false!")
	}
	emptyTrans.Witness = segwit

	for i := 0; i < len(emptyTrans.Vins); i++ {
		emptyTrans.Vins[i].inType = int(TypeP2PKH)
		emptyTrans.Vins[i].scriptPub = nil
		script, err := txHashes[i].encodeToScript(nil, SegwitON)
		if err != nil {
			return "", err
		}
		emptyTrans.Vins[i].scriptSig = script

	}

	ret, err := emptyTrans.encodeToBytes(SegwitON)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(ret), nil
}

func VerifyRawTransaction(txHex string, unlockData []TxUnlock, SegwitON bool, addressPrefix AddressPrefix) bool {
	txBytes, err := hex.DecodeString(txHex)
	if err != nil {
		return false
	}

	signedTrans, err := DecodeRawTransaction(txBytes, SegwitON)
	if err != nil {
		return false
	}

	if len(signedTrans.Vins) != len(unlockData) {
		return false
	}

	emptyTrans := signedTrans.cloneEmpty()

	txHash, err := emptyTrans.getHashesForSig(unlockData, SegwitON, addressPrefix)
	if err != nil {
		return false
	}

	for i := 0; i < len(signedTrans.Vins); i++ {
		if signedTrans.Vins[i].inType == TypeP2PKH || signedTrans.Vins[i].inType == TypeP2WPKH || signedTrans.Vins[i].inType == TypeBech32 {
			sigpub, sigType, err := decodeFromScriptBytes(signedTrans.Vins[i].scriptSig)
			if err != nil {
				return false
			}

			txHash[i].Normal.SigPub = *sigpub
			txHash[i].Normal.SigType = sigType
		} else if signedTrans.Vins[i].inType == TypeMultiSig {
			sigpub, sigType, err := decodeMultiBytes(signedTrans.Vins[i].scriptMulti)
			if err != nil {
				return false
			}
			for j := 0; j < len(sigpub); j++ {
				txHash[i].Multi[j].SigPub = sigpub[j]
				txHash[i].Multi[j].SigType = sigType[j]
			}
		}
	}

	for _, t := range txHash {
		th, _ := hex.DecodeString(t.Hash)
		if t.NRequired == 0 {
			pubkey := owcrypt.PointDecompress(t.Normal.SigPub.Pubkey, owcrypt.ECC_CURVE_SECP256K1)[1:]
			if owcrypt.Verify(pubkey, nil, 0, th, 32, t.Normal.SigPub.Signature, owcrypt.ECC_CURVE_SECP256K1) != owcrypt.SUCCESS {
				return false
			}
		} else {
			count := 0
			for i := 0; i < int(t.NRequired); i++ {
				for j := count; j < len(t.Multi); j++ {
					pubkey := owcrypt.PointDecompress(t.Multi[j].SigPub.Pubkey, owcrypt.ECC_CURVE_SECP256K1)[1:]
					if owcrypt.Verify(pubkey, nil, 0, th, 32, t.Multi[i].SigPub.Signature, owcrypt.ECC_CURVE_SECP256K1) == owcrypt.SUCCESS {
						count++
						break
					}
				}
			}
			if count != int(t.NRequired) {
				return false
			}
		}
	}
	return true
}
