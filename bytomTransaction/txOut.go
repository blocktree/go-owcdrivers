package bytomTransaction

import (
	"errors"
)

type TxOut struct {
	AssetID        []byte
	ControlProgram []byte
	Amount         []byte
}

func (out *TxOut) SetAssetID() {
	out.AssetID = BTMAssetID
}

func (out *TxOut) SetControlProgram(address string) error {
	witnessVersion, witnessProgram, err := decodeSegWitAddress(address)
	if err != nil {
		return err
	}
	if witnessVersion != DefaultWitnessVersion {
		return errors.New("Witness version unsupported!")
	}

	if len(witnessProgram) != 20 && len(witnessProgram) != 32 {
		return errors.New("Witness unsupported!")
	}

	out.ControlProgram = append([]byte{0x00, byte(len(witnessProgram))}, witnessProgram...)

	out.ControlProgram = append([]byte{byte(len(out.ControlProgram))}, out.ControlProgram...)

	return nil
}

func (out TxOut) GetAmount() uint64 {
	return uvarintToUint64(out.Amount)
}

func (out *TxOut) SetAmount(amount uint64) {
	out.Amount = uint64ToUvarint(amount)
}

func newTxOutForEmptyTrans(vout []Vout) ([]TxOut, error) {
	if vout == nil || len(vout) == 0 {
		return nil, errors.New("No address to send when create an empty transaction!")
	}

	var ret []TxOut

	for _, v := range vout {
		var tmp TxOut
		tmp.SetAssetID()
		if nil != tmp.SetControlProgram(v.Address) {
			return nil, errors.New("Invalid address!")
		}
		tmp.SetAmount(v.Amount)

		ret = append(ret, tmp)
	}
	return ret, nil
}

func (out TxOut) toBytes() ([]byte, error) {

	if out.Amount == nil || len(out.Amount) == 0 {
		return nil, errors.New("Invalid amount!")
	}

	if out.AssetID == nil || len(out.AssetID) != 32 {
		return nil, errors.New("Invalid asset ID!")
	}

	if out.ControlProgram == nil || len(out.ControlProgram) == 0 {
		return nil, errors.New("Invalid control program!")
	}

	var ret []byte

	ret = append(ret, out.AssetID...)
	ret = append(ret, out.Amount...)
	ret = append(ret, DefaultOutVersion)
	ret = append(ret, out.ControlProgram...)
	ret = append([]byte{byte(len(ret))}, ret...)
	ret = append([]byte{DefaultAssetVersion}, ret...)

	ret = append(ret, 0x00) // witness  length
	return ret, nil
}

func decodeOutputScript(script []byte) ([]byte, []byte, []byte, error) {
	limit := len(script)
	index := 0

	if index+32 > limit {
		return nil, nil, nil, errors.New("Invalid output script data!")
	}

	assetID := script[index : index+32]
	index += 32

	offset := 1
	for {
		if index+1 > limit {
			return nil, nil, nil, errors.New("Invalid output script data!")
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
		return nil, nil, nil, errors.New("Invalid output script data!")
	}
	if script[index] != DefaultOutVersion {
		return nil, nil, nil, errors.New("Invalid output script data!")
	}
	index++

	if index+1 > limit {
		return nil, nil, nil, errors.New("Invalid output script data!")
	}

	sciiptLen := script[index]
	if sciiptLen == 0 {
		return nil, nil, nil, errors.New("Invalid output script data!")
	}

	if index+1+int(sciiptLen) > limit {
		return nil, nil, nil, errors.New("Invalid output script data!")
	}
	controlProgram := script[index : index+1+int(sciiptLen)]
	index += int(sciiptLen)

	if index+1 != limit {
		return nil, nil, nil, errors.New("Invalid output script data!")
	}

	return assetID, amount, controlProgram, nil
}
