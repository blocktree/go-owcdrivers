package hypercashTransaction

import (
	"encoding/hex"
	"github.com/blocktree/go-owcrypt"
	"github.com/pkg/errors"
	"strings"
)

type TxStruct struct {
	TxVersion  []byte
	SerType    []byte
	TxIns      []*TxIn
	TxOuts     []*TxOut
	LockTime   []byte
	Expiry     []byte
}

func NewTxStruct(ins []Vin, outs []Vout, locktime, expiry uint32) (*TxStruct, error) {
	var txStruct TxStruct

	txStruct.TxVersion = uint16ToLittleEndianBytes(DefaultTxVersion)

	if ins == nil || len(ins) == 0 {
		return nil, errors.New("Missing input!")
	}

	if outs == nil || len(outs) == 0 {
		return nil, errors.New("Missing output!")
	}

	for _, in := range ins {
		input, err := in.NewTxIn()
		if err != nil {
			return nil, err
		}

		txStruct.TxIns = append(txStruct.TxIns, input)
	}

	for _, out := range outs {
		output,err := out.NewTxOut()
		if err != nil {
			return nil, err
		}

		txStruct.TxOuts = append(txStruct.TxOuts, output)
	}

	txStruct.LockTime = uint32ToLittleEndianBytes(locktime)
	txStruct.Expiry = uint32ToLittleEndianBytes(expiry)

	return &txStruct, nil
}

func (tx *TxStruct) ToBytes(index uint64, serType uint16) ([]byte, error) {
	ret := make([]byte, 0)
	tx.SerType = uint16ToLittleEndianBytes(serType)

	if serType == TxSerializeNoWitness || serType == TxSerializeFull{
		ret = append(ret, tx.TxVersion...)
		ret = append(ret, tx.SerType...)
		ret = append(ret, varIntToBytes(uint64(len(tx.TxIns)))...)
		for _, in := range tx.TxIns {
			ret = append(ret, in.ToBytes()...)
		}
		ret = append(ret, varIntToBytes(uint64(len(tx.TxOuts)))...)
		for _, out := range tx.TxOuts {
			ret = append(ret, out.ToBytes()...)
		}
		ret = append(ret, tx.LockTime...)
		ret = append(ret, tx.Expiry...)
	} else if serType == TxSerializeWitnessSigning {
		ret = append(ret, tx.TxVersion...)
		ret = append(ret, tx.SerType...)
		if index >= uint64(len(tx.TxIns)) {
			return nil, errors.New("Index too big!")
		}

		ret = append(ret, varIntToBytes(uint64(len(tx.TxIns)))...)
		for i := uint64(0); i < uint64(len(tx.TxIns)); i ++ {
			if i == index {
				ret = append(ret, tx.TxIns[i].LockScript...)
			} else {
				ret = append(ret, 0x00)
			}
		}
	} else {
		return nil, errors.New("Serialize type not support!")
	}

	return ret, nil
}

func (tx *TxStruct) GetHash(index uint64) ([]byte, error) {
	prefixBytes, err := tx.ToBytes(0, TxSerializeNoWitness)
	if err != nil {
		return nil, err
	}
	prefixHash := owcrypt.Hash(prefixBytes, 0, owcrypt.HASH_ALG_BLAKE256)

	witnessBytes, err := tx.ToBytes(index, TxSerializeWitnessSigning)
	if err != nil {
		return nil, err
	}
	witnessHash := owcrypt.Hash(witnessBytes, 0, owcrypt.HASH_ALG_BLAKE256)
	data := uint32ToLittleEndianBytes(uint32(SigHashAll))
	data = append(data, prefixHash...)
	data = append(data, witnessHash...)

	return owcrypt.Hash(data, 0, owcrypt.HASH_ALG_BLAKE256), nil
}

func GetVinList(emptyTrans string) ([]Vin, error) {
	trans := strings.Split(emptyTrans, ":")
	if len(trans) <= 1 {
		return nil, errors.New("Invalid transaction hex!")
	}

	tx, err := hex.DecodeString(trans[0])
	if err != nil {
		return nil, errors.New("Invalid transaction hex!")
	}

	limit := len(tx)

	index := 0

	if index + 4 > limit {
		return nil, errors.New("Invalid transaction hex!")
	}
	index += 4

	if index + 1 > limit {
		return nil, errors.New("Invalid transaction hex!")
	}
	count := int(tx[index])
	index ++
	if count <= 0 || count != len(trans) - 1{
		return nil, errors.New("Invalid transaction hex!")
	}
	ret := make([]Vin, 0)
	for i := 0; i < count; i ++ {
		if index + 32 > limit {
			return nil, errors.New("Invalid transaction hex!")
		}
		txid := reverseBytesToHex(tx[index:index+32])
		index += 32
		if index + 9 > limit {
			return nil, errors.New("Invalid transaction hex!")
		}
		vout := littleEndianBytesToUint32(tx[index:index+4])
		index += 9

		ret = append(ret, Vin{
			TxID:txid,
			Vout:vout,
		})
	}

	return ret, nil
}