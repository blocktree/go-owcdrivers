package hypercashTransaction

import (
	"encoding/hex"
	"github.com/blocktree/go-owcrypt"
	"github.com/pkg/errors"
	"strings"
)

type Vin struct {
	TxID       string
	Vout       uint32
	Tree       byte
	Amount     uint64
	LockScript string
	BlockHeight uint32
	BlockIndex uint32
}

type Vout struct {
	Amount uint64
	PkScriptVersion uint16
	Address string
}

func CreateEmptyTransactionAndHash(ins []Vin, outs []Vout, locktime, expiry uint32)(string, []string, error) {

	if ins == nil || len(ins) == 0 || outs == nil || len(outs) == 0 {
		return "", nil, errors.New("Check the count of input and output!")
	}
	tx, err := NewTxStruct(ins, outs, locktime, expiry)
	if err != nil {
		return "", nil, err
	}

	txBytes, err := tx.ToBytes(0, TxSerializeFull)
	if err != nil {
		return "", nil, err
	}

	emptyTrans := hex.EncodeToString(txBytes)
	var hashes []string

	for index := uint64(0); index < uint64(len(ins)); index++ {
		hash, err := tx.GetHash(index)
		if err != nil {
			return "", nil, err
		}

		hashes = append(hashes, hex.EncodeToString(hash))

		emptyTrans += ":"
		emptyTrans += hex.EncodeToString(tx.TxIns[index].LockScript)
		emptyTrans += "/"
		emptyTrans += hex.EncodeToString(tx.TxIns[index].SignatureScript)
	}

	return emptyTrans, hashes, nil
}

func CreateOmniEmptyTransactionAndHash(ins []Vin, to, change  *Vout, amount uint64,propertyID uint32, locktime, expiry uint32) (string, []string, error) {

	if ins == nil || len(ins) == 0 {
		return "", nil, errors.New("Check the count of input!")
	}

	if to == nil {
		return "", nil, errors.New("Miss output!")
	}

	outs := make([]Vout, 0)
	outs = append(outs, *to, *to)
	if change != nil {
		outs = append(outs, *change)
	}

	tx, err := NewTxStruct(ins, outs, locktime, expiry)
	if err != nil {
		return "", nil, err
	}

	tx.TxOuts[1].Amount = uint64ToLittleEndianBytes(0)
	tx.TxOuts[1].PKScript = createPayloadSimpleSend(propertyID, amount)

	txBytes, err := tx.ToBytes(0, TxSerializeFull)
	if err != nil {
		return "", nil, err
	}

	emptyTrans := hex.EncodeToString(txBytes)
	var hashes []string

	for index := uint64(0); index < uint64(len(ins)); index++ {
		hash, err := tx.GetHash(index)
		if err != nil {
			return "", nil, err
		}

		hashes = append(hashes, hex.EncodeToString(hash))

		emptyTrans += ":"
		emptyTrans += hex.EncodeToString(tx.TxIns[index].LockScript)
		emptyTrans += "/"
		emptyTrans += hex.EncodeToString(tx.TxIns[index].SignatureScript)
	}

	return emptyTrans, hashes, nil
}

func SignTransaction(hashStr string, prikey []byte) ([]byte, error) {
	hash, err := hex.DecodeString(hashStr)
	if err != nil {
		return nil, err
	}
	if hash == nil || len(hash) != 32 {
		return nil, errors.New("Invalid transaction hash!")
	}

	signature, retCode := owcrypt.Signature(prikey, nil, 0, hash, 32, owcrypt.ECC_CURVE_SECP256K1)
	if retCode != owcrypt.SUCCESS {
		return nil, errors.New("Failed in signature!")
	}
	serilizeS(signature)

	return signature, nil
}

func VerifyAndCombineTransaction(emptyTrans string, sigPub []*SigPub) (bool, string) {
	ret := make([]byte, 0)
	transData := strings.Split(emptyTrans, ":")
	if transData == nil || len(transData) <= 1 {
		return false, ""
	}

	if len(transData) - 1 != len(sigPub) {
		return false, ""
	}

	txBytes, err := hex.DecodeString(transData[0])
	if err != nil {
		return false, ""
	}

	serilizeFull := uint16ToLittleEndianBytes(TxSerializeFull)
	if serilizeFull[0] != txBytes[2] || serilizeFull[1] != txBytes[3] {
		return false, ""
	}

	ret = append(ret, txBytes...)
	ret = append(ret, varIntToBytes(uint64(len(sigPub)))...)

	serilizeNoWitness := uint16ToLittleEndianBytes(TxSerializeNoWitness)
	txBytes[2] = serilizeNoWitness[0]
	txBytes[3] = serilizeNoWitness[1]

	serilizeWitnessSign := uint16ToLittleEndianBytes(TxSerializeWitnessSigning)

	prefixHash := owcrypt.Hash(txBytes, 0, owcrypt.HASH_ALG_BLAKE256)
	for i, data := range transData[1:] {
		sepStr := strings.Split(data, "/")
		if sepStr == nil || len(sepStr) != 2 {
			return false, ""
		}

		witnessBytes := uint16ToLittleEndianBytes(DefaultTxVersion)
		witnessBytes =append(witnessBytes, serilizeWitnessSign...)
		witnessBytes = append(witnessBytes, varIntToBytes(uint64(len(sigPub)))...)
		for j := 0; j < len(sigPub); j++ {
			if j == i {
				lockscript, err := hex.DecodeString(sepStr[0])
				if err != nil {
					return false, ""
				}
				witnessBytes = append(witnessBytes, lockscript...)
			} else {
				witnessBytes = append(witnessBytes, 0x00)
			}
		}
		witnessHash := owcrypt.Hash(witnessBytes, 0, owcrypt.HASH_ALG_BLAKE256)
		hashData := uint32ToLittleEndianBytes(uint32(SigHashAll))
		hashData = append(hashData, prefixHash...)
		hashData = append(hashData, witnessHash...)


		hash := owcrypt.Hash(hashData, 0, owcrypt.HASH_ALG_BLAKE256)

		pubkey := owcrypt.PointDecompress(sigPub[i].PublicKey, owcrypt.ECC_CURVE_SECP256K1)[1:]

		if owcrypt.SUCCESS != owcrypt.Verify(pubkey, nil, 0, hash, 32, sigPub[i].Signature, owcrypt.ECC_CURVE_SECP256K1) {
			return false, ""
		}

		sigScript, err := hex.DecodeString(sepStr[1])
		if err != nil {
			return false, ""
		}

		ret = append(ret, sigScript...)
		ret = append(ret, sigPub[i].encodeToScript(SigHashAll)...)
	}

	return true, hex.EncodeToString(ret)
}

