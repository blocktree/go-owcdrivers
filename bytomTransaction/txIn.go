package bytomTransaction

import (
	"encoding/hex"
	"errors"
)

type TxIn struct {
	SourceID       []byte
	SourcePosition []byte
	AssetID        []byte
	Amount         []byte
	ControlProgram []byte
	SigPub         *SigPub
	MultiSig       []byte
}

func (in *TxIn) SetSourceID(hexID string) error {
	sourceID, err := hex.DecodeString(hexID)
	if err != nil {
		return err
	}
	in.SourceID = sourceID
	return nil
}

func (in TxIn) GetSourceID() string {
	return hex.EncodeToString(in.SourceID)
}

func (in *TxIn) SetSourcePosition(pos uint64) {
	in.SourcePosition = uint64ToUvarint(pos)
}

func (in TxIn) GetSourcePosition() uint64 {
	return uvarintToUint64(in.SourcePosition)
}

func (in *TxIn) SetAssetID(hexID string) error {
	assetID, err := hex.DecodeString(hexID)
	if err != nil {
		return err
	}
	in.AssetID = assetID
	return nil
}

func (in TxIn) GetAssetID() string {
	return hex.EncodeToString(in.AssetID)
}

func (in *TxIn) SetAmount(amount uint64) {
	in.Amount = uint64ToUvarint(amount)
}

func (in TxIn) GetAmount() uint64 {
	return uvarintToUint64(in.Amount)
}

func (in *TxIn) SetControlProgram(hexProgram string) error {
	program, err := hex.DecodeString(hexProgram)
	if err != nil {
		return err
	}
	in.ControlProgram = program
	return nil
}

func (in TxIn) GetControlProgram() string {
	return hex.EncodeToString(in.ControlProgram)
}

func newTxInForEmptyTrans(vin []Vin) ([]TxIn, error) {
	if vin == nil || len(vin) == 0 {
		return nil, errors.New("No input found when create an empty transaction!")
	}
	var ret []TxIn

	for _, v := range vin {
		var in TxIn
		if nil != in.SetSourceID(v.SourceID) {
			return nil, errors.New("Invalid source ID!")
		}
		in.SetSourcePosition(v.SourcePosition)

		if nil != in.SetAssetID(v.AssetID) {
			return nil, errors.New("Invalid asset ID!")
		}
		in.SetAmount(v.Amount)

		if nil != in.SetControlProgram(v.ControlProgram) {
			return nil, errors.New("Invalid control program!")
		}

		in.SigPub = nil

		ret = append(ret, in)
	}
	return ret, nil
}

func (in TxIn) toBytes() ([]byte, error) {

	if in.SourceID == nil || len(in.SourceID) != 32 {
		return nil, errors.New("No source ID found or source ID is in wrong length!")
	}
	if in.AssetID == nil || len(in.AssetID) != 32 {
		return nil, errors.New("No asset ID found or asset ID is in wrong length!")
	}
	if in.ControlProgram == nil || (len(in.ControlProgram) != 22 && len(in.ControlProgram) != 34) {
		return nil, errors.New("No control program found or control program is in wrong length!")
	}
	if in.SourcePosition == nil || len(in.SourcePosition) == 0 {
		return nil, errors.New("No source position found!")
	}
	if in.Amount == nil || len(in.Amount) == 0 {
		return nil, errors.New("No amount found!")
	}

	var ret []byte

	ret = append(ret, in.SourceID...)
	ret = append(ret, in.AssetID...)
	ret = append(ret, in.Amount...)
	ret = append(ret, in.SourcePosition...)
	ret = append(ret, 0x01, byte(len(in.ControlProgram)))
	ret = append(ret, in.ControlProgram...)

	ret = append([]byte{byte(len(ret))}, ret...)
	ret = append([]byte{0x01}, ret...)
	ret = append([]byte{byte(len(ret))}, ret...)

	if in.SigPub == nil && in.MultiSig == nil {
		ret = append(ret, 0x01, 0x00)
	} else {
		if in.SigPub == nil {
			ret = append(ret, in.MultiSig...)
		} else {
			spBytes, err := in.SigPub.toBytes()
			if err != nil {
				return nil, err
			}

			ret = append(ret, spBytes...)
		}

	}

	ret = append([]byte{DefaultAssetVersion}, ret...)
	return ret, nil
}

func decodeCommitment(script []byte) ([]byte, []byte, []byte, []byte, []byte, error) {
	limit := len(script)
	index := 0
	if index+1 > limit {
		return nil, nil, nil, nil, nil, errors.New("Invalid commitment data!")
	}

	if script[index] != byte(DefaultVMVersion) {
		return nil, nil, nil, nil, nil, errors.New("Invalid VM version!")
	}
	index++

	if index+1 > limit {
		return nil, nil, nil, nil, nil, errors.New("Invalid commitment data!")
	}

	if script[index] != byte(limit-2) {
		return nil, nil, nil, nil, nil, errors.New("nvalid commitment data!")
	}
	index++

	if index+32 > limit {
		return nil, nil, nil, nil, nil, errors.New("Invalid commitment data!")
	}

	sourceID := script[index : index+32]
	index += 32

	if index+32 > limit {
		return nil, nil, nil, nil, nil, errors.New("Invalid commitment data!")
	}
	assetID := script[index : index+32]
	index += 32

	offset := 1
	for {
		if index+1 > limit {
			return nil, nil, nil, nil, nil, errors.New("Invalid commitment data!")
		}

		if script[index+offset-1] < 0x80 {
			break
		} else {
			offset++
			continue
		}
	}
	amount := script[index : index+offset]
	index += offset

	if index+1 > limit {
		return nil, nil, nil, nil, nil, errors.New("Invalid commitment data!")
	}

	sourcePos := script[index : index+1]
	index++

	if index+1 > limit {
		return nil, nil, nil, nil, nil, errors.New("Invalid commitment data!")
	}

	if script[index] != byte(DefaultVMVersion) {
		return nil, nil, nil, nil, nil, errors.New("Invalid VM version!")
	}
	index++
	if index+1 > limit {
		return nil, nil, nil, nil, nil, errors.New("Invalid commitment data!")
	}
	controlLen := int(script[index])
	if controlLen == 0 {
		return nil, nil, nil, nil, nil, errors.New("Invalid commitment data!")
	}

	if index+1+controlLen != limit {
		return nil, nil, nil, nil, nil, errors.New("Invalid commitment data!")
	}

	controlProgram := script[index+1:]
	return sourceID, assetID, amount, sourcePos, controlProgram, nil
}
