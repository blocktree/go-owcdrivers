package bytomTransaction

import (
	"errors"

	"github.com/blocktree/go-owcrypt"
)

type Transaction struct {
	Version   []byte
	TimeRange []byte
	Inputs    []TxIn
	Outputs   []TxOut
}

func (t *Transaction) SetTransVersion(ver uint64) {
	t.Version = uint64ToUvarint(ver)
}

func (t *Transaction) SetTimeRange(time uint64) {
	t.TimeRange = uint64ToUvarint(time)
}

func (t *Transaction) GetTimeRange() uint64 {
	return uvarintToUint64(t.TimeRange)
}

func newEmptyTransaction(vins []Vin, vouts []Vout, timeRange uint64) (*Transaction, error) {
	txIn, err := newTxInForEmptyTrans(vins)
	if err != nil {
		return nil, err
	}

	txOut, err := newTxOutForEmptyTrans(vouts)
	if err != nil {
		return nil, err
	}

	var ret Transaction

	ret.Inputs = txIn
	ret.Outputs = txOut
	ret.SetTransVersion(DefaultTransactionVersion)
	ret.SetTimeRange(timeRange)

	return &ret, nil
}

func (t Transaction) toBytes() ([]byte, error) {
	if t.Inputs == nil || len(t.Inputs) == 0 {
		return nil, errors.New("No input found in the transaction struct!")
	}

	if t.Outputs == nil || len(t.Outputs) == 0 {
		return nil, errors.New("No output found in the transaction struct!")
	}

	if t.TimeRange == nil || len(t.TimeRange) == 0 {
		return nil, errors.New("No time range found in the transaction struct!")
	}

	if t.Version == nil || len(t.Version) == 0 {
		return nil, errors.New("No transaction version found in the transaction struct!")
	}

	ret := []byte{}
	ret = append(ret, DefaultSerFlags)
	ret = append(ret, t.Version...)
	ret = append(ret, t.TimeRange...)

	ret = append(ret, byte(len(t.Inputs)))

	for _, in := range t.Inputs {
		inBytes, err := in.toBytes()
		if err != nil {
			return nil, err
		}
		ret = append(ret, inBytes...)
	}

	ret = append(ret, byte(len(t.Outputs)))

	for _, out := range t.Outputs {
		outBytes, err := out.toBytes()
		if err != nil {
			return nil, err
		}
		ret = append(ret, outBytes...)
	}
	return ret, nil
}

func DecodeRawTransaction(txBytes []byte) (*Transaction, error) {
	limit := len(txBytes)

	if limit == 0 {
		return nil, errors.New("Invalid transaction data!")
	}

	var rawTx Transaction

	index := 0

	if index+1 > limit {
		return nil, errors.New("Invalid transaction data!")
	}

	if txBytes[index] != DefaultSerFlags {
		return nil, errors.New("Invalid transaction serflags!")
	}
	index++

	// get transaction version
	offset := 1
	for {
		if index+1 > limit {
			return nil, errors.New("Invalid transaction data!")
		}
		if txBytes[index+offset-1] < 0x80 {
			break
		} else {
			index++
			continue
		}
	}

	rawTx.Version = txBytes[index : index+offset]
	index += offset

	// get range time
	offset = 1
	for {
		if index+1 > limit {
			return nil, errors.New("Invalid transaction data!")
		}
		if txBytes[index+offset-1] < 0x80 {
			break
		} else {
			offset++
			continue
		}
	}

	rawTx.TimeRange = txBytes[index : index+offset]
	index += offset

	//get count of inputs
	if index+1 > limit {
		return nil, errors.New("Invalid transaction data!")
	}
	numOfVins := txBytes[index]
	index++
	if numOfVins <= 0 {
		return nil, errors.New("Invalid transaction data!")
	}

	// get vins
	for i := byte(0); i < numOfVins; i++ {
		var in TxIn
		// get asset version of inputs
		if index+1 > limit {
			return nil, errors.New("Invalid transaction data!")
		}
		if txBytes[index] != DefaultAssetVersion {
			return nil, errors.New("Invalid input asset version!")
		}
		index++
		//get commitment length
		if index+1 > limit {
			return nil, errors.New("Invalid transaction data!")
		}
		commitLength := int(txBytes[index])
		if commitLength == 0 {
			return nil, errors.New("Invalid transaction data!")
		}
		index++

		if index+commitLength > limit {
			return nil, errors.New("Invalid transaction data!")
		}

		sourceID, assetID, amount, sourcePos, controlProgram, err := decodeCommitment(txBytes[index : index+commitLength])
		if err != nil {
			return nil, err
		}
		in.SourceID = sourceID
		in.AssetID = assetID
		in.Amount = amount
		in.SourcePosition = sourcePos
		in.ControlProgram = controlProgram

		index += commitLength

		if index+1 > limit {
			return nil, errors.New("Invalid transaction data!")
		}
		if txBytes[index] == 0x01 {
			if index+2 > limit {
				return nil, errors.New("Invalid transaction data!")
			}
			if txBytes[index+1] != 0x00 {
				return nil, errors.New("Invalid transaction data!")
			} else {
				in.SigPub = nil
				index += 2
			}
		} else {
			spScriptLen := int(txBytes[index])
			if spScriptLen == 0 {
				return nil, errors.New("Invalid transaction data!")
			}
			index++
			if index+2 > limit {
				return nil, errors.New("Invalid transaction data!")
			}
			if txBytes[index] != 0x02 || txBytes[index+1] != 0x40 {
				return nil, errors.New("Invalid transaction data!")
			}
			index += 2
			if index+64 > limit {
				return nil, errors.New("Invalid transaction data!")
			}
			sig := txBytes[index : index+64]
			index += 64
			if index+1 > limit {
				return nil, errors.New("Invalid transaction data!")
			}
			if txBytes[index] != 32 {
				return nil, errors.New("Invalid transaction data!")
			}
			index++
			if index+32 > limit {
				return nil, errors.New("Invalid transaction data!")
			}
			pub := txBytes[index : index+32]
			index += 32
			in.SigPub = &SigPub{sig, pub}
		}
		rawTx.Inputs = append(rawTx.Inputs, in)
	}
	//get count of outputs
	if index+1 > limit {
		return nil, errors.New("Invalid transaction data!")
	}
	numOfVouts := txBytes[index]
	index++
	if numOfVouts == 0 {
		return nil, errors.New("Invalid transaction data!")
	}

	for i := byte(0); i < numOfVouts; i++ {
		var out TxOut
		if index+1 > limit {
			return nil, errors.New("Invalid transaction data!")
		}

		if txBytes[index] != DefaultOutVersion {
			return nil, errors.New("Invalid transaction data!")
		}
		index++
		//get length of out script
		if index+1 > limit {
			return nil, errors.New("Invalid transaction data!")
		}
		oLen := txBytes[index]
		if oLen == 0 {
			return nil, errors.New("Invalid transaction data!")
		}
		index++
		if index+int(oLen) > limit {
			return nil, errors.New("Invalid transaction data!")
		}
		assetID, amount, controlProgram, err := decodeOutputScript(txBytes[index : index+int(oLen)])
		if err != nil {
			return nil, err
		}
		out.AssetID = assetID
		out.Amount = amount
		out.ControlProgram = controlProgram
		index += int(oLen)

		rawTx.Outputs = append(rawTx.Outputs, out)

		if index+1 > limit {
			return nil, errors.New("Invalid transaction data!")
		}
		// witness length
		if txBytes[index] != 0x00 {
			return nil, errors.New("Invalid transaction data!")
		}
		index++
	}

	if index != limit {
		return nil, errors.New("Invalid transaction data!")
	}
	return &rawTx, nil
}

func (t Transaction) getInputID(index int) ([]byte, error) {
	msgBytes := []byte{}

	if t.Inputs == nil || len(t.Inputs) == 0 {
		return nil, errors.New("No inputs found in the transaction struct!")
	}

	if len(t.Inputs) < index {
		return nil, errors.New("Index of transaction inputs is out of range!")
	}

	if t.Inputs[index].SourceID == nil || len(t.Inputs[index].SourceID) != 32 {
		return nil, errors.New("Invalid source ID of input!")
	}

	msgBytes = append(msgBytes, t.Inputs[index].SourceID...)

	if t.Inputs[index].AssetID == nil || len(t.Inputs[index].AssetID) != 32 {
		return nil, errors.New("Invalid asset ID of input!")
	}

	msgBytes = append(msgBytes, t.Inputs[index].AssetID...)

	msgBytes = append(msgBytes, uint64ToLittleEndianBytes(t.Inputs[index].GetAmount())...)

	msgBytes = append(msgBytes, uint64ToLittleEndianBytes(t.Inputs[index].GetSourcePosition())...)

	msgBytes = append(msgBytes, uint64ToLittleEndianBytes(DefaultVMVersion)...)

	if t.Inputs[index].ControlProgram == nil || len(t.Inputs[index].ControlProgram) == 0 {
		return nil, errors.New("Invalid control program!")
	}

	msgBytes = append(msgBytes, byte(len(t.Inputs[index].ControlProgram)))
	msgBytes = append(msgBytes, t.Inputs[index].ControlProgram...)

	hash := owcrypt.Hash(msgBytes, 0, owcrypt.HASH_ALG_SHA3_256)

	pre := []byte(HashPrefixEntry + HashPrefixOutput)

	msgBytes = append(pre, hash...)

	hash = owcrypt.Hash(msgBytes, 0, owcrypt.HASH_ALG_SHA3_256)

	hash = owcrypt.Hash(hash, 0, owcrypt.HASH_ALG_SHA3_256)

	pre = []byte(HashPrefixEntry + HashPrefixSpend)

	msgBytes = append(pre, hash...)

	return owcrypt.Hash(msgBytes, 0, owcrypt.HASH_ALG_SHA3_256), nil
}

func (t Transaction) getMuxID() ([]byte, error) {
	var spendID [][]byte

	if t.Inputs == nil {
		return nil, errors.New("No inputs found in the transaction struct!")
	}

	for i := 0; i < len(t.Inputs); i++ {
		spend, err := t.getInputID(i)
		if err != nil {
			return nil, err
		}
		spendID = append(spendID, spend)
	}

	var msgBytes []byte

	msgBytes = append(msgBytes, byte(len(spendID)))

	for i := 0; i < len(spendID); i++ {
		msgBytes = append(msgBytes, spendID[i]...)
		msgBytes = append(msgBytes, t.Inputs[i].AssetID...)
		msgBytes = append(msgBytes, uint64ToLittleEndianBytes(t.Inputs[i].GetAmount())...)
		msgBytes = append(msgBytes, uint64ToLittleEndianBytes(t.Inputs[i].GetSourcePosition())...)
	}

	msgBytes = append(msgBytes, uint64ToLittleEndianBytes(DefaultVMVersion)...)

	msgBytes = append(msgBytes, 0x01, Op_true)

	innerHash := owcrypt.Hash(msgBytes, 0, owcrypt.HASH_ALG_SHA3_256)

	pre := []byte(HashPrefixEntry + HashPrefixMux)

	msgBytes = append(pre, innerHash...)

	return owcrypt.Hash(msgBytes, 0, owcrypt.HASH_ALG_SHA3_256), nil
}

func (t Transaction) getOutID(index int) ([]byte, error) {
	muxID, err := t.getMuxID()
	if err != nil {
		return nil, err
	}
	if t.Outputs == nil || len(t.Outputs) == 0 {
		return nil, errors.New("No outputs found in transaction struct!")
	}

	if t.Outputs[index].AssetID == nil || len(t.Outputs[index].AssetID) != 32 {
		return nil, errors.New("Miss asset ID in the output!")
	}

	if t.Outputs[index].Amount == nil || len(t.Outputs[index].Amount) == 0 {
		return nil, errors.New("Miss amount in the output!")
	}

	if t.Outputs[index].ControlProgram == nil || len(t.Outputs[index].ControlProgram) == 0 {
		return nil, errors.New("Miss control program amount in the output!")
	}

	msgBytes := []byte{}

	msgBytes = append(msgBytes, muxID...)

	msgBytes = append(msgBytes, t.Outputs[index].AssetID...)

	msgBytes = append(msgBytes, uint64ToLittleEndianBytes(t.Outputs[index].GetAmount())...)

	msgBytes = append(msgBytes, uint64ToLittleEndianBytes(uint64(index))...)

	msgBytes = append(msgBytes, uint64ToLittleEndianBytes(DefaultVMVersion)...)

	msgBytes = append(msgBytes, t.Outputs[index].ControlProgram...)

	innerHash := owcrypt.Hash(msgBytes, 0, owcrypt.HASH_ALG_SHA3_256)

	pre := []byte(HashPrefixEntry + HashPrefixOutput)

	msgBytes = append(pre, innerHash...)

	return owcrypt.Hash(msgBytes, 0, owcrypt.HASH_ALG_SHA3_256), nil
}

func (t Transaction) getTxID() ([]byte, error) {
	var outID [][]byte

	if t.Outputs == nil {
		return nil, errors.New("No output found in transaction struct!")
	}

	for i := 0; i < len(t.Outputs); i++ {
		out, err := t.getOutID(i)
		if err != nil {
			return nil, err
		}
		outID = append(outID, out)
	}

	msgBytes := []byte{}

	msgBytes = append(msgBytes, uint64ToLittleEndianBytes(DefaultTransactionVersion)...)

	if t.TimeRange == nil {
		return nil, errors.New("No time range found!")
	}
	msgBytes = append(msgBytes, uint64ToLittleEndianBytes(t.GetTimeRange())...)

	msgBytes = append(msgBytes, byte(len(t.Outputs)))

	for _, o := range outID {
		msgBytes = append(msgBytes, o...)
	}

	innerHash := owcrypt.Hash(msgBytes, 0, owcrypt.HASH_ALG_SHA3_256)

	pre := []byte(HashPrefixEntry + HashPrefixTxheader)

	msgBytes = append(pre, innerHash...)

	return owcrypt.Hash(msgBytes, 0, owcrypt.HASH_ALG_SHA3_256), nil
}

func (t Transaction) getSigHash(index int) ([]byte, error) {
	spendID, err := t.getInputID(index)
	if err != nil {
		return nil, err
	}

	txID, err := t.getTxID()
	if err != nil {
		return nil, err
	}

	return owcrypt.Hash(append(spendID, txID...), 0, owcrypt.HASH_ALG_SHA3_256), nil
}

func (t Transaction) cloneEmpty() Transaction {
	var ret Transaction
	ret.Version = append(ret.Version, t.Version...)
	ret.Inputs = append(ret.Inputs, t.Inputs...)
	ret.Outputs = append(ret.Outputs, t.Outputs...)
	ret.TimeRange = append(ret.TimeRange, t.TimeRange...)
	for i := 0; i < len(ret.Inputs); i++ {
		ret.Inputs[i].SigPub = nil
	}
	return ret
}
