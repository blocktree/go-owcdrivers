package elastosTransaction

import (
	"errors"
)

type Output struct {
	AssetID     []byte
	Amount      []byte
	Lock        []byte
	ProgramHash []byte
}

func (out Vout) NewOutput() (*Output, error) {
	assetID, err := reverseHexToBytes(out.AssetID)
	if err != nil {
		return nil, errors.New("Invalid Asset ID!")
	}

	amount := uint64ToLittleEndianBytes(out.Amount)

	programHash, err := GetProgramHashFromAddress(out.Address)
	if err != nil {
		return nil, err
	}

	return &Output{
		AssetID:     assetID,
		Amount:      amount,
		Lock:        []byte{0, 0, 0, 0},
		ProgramHash: programHash,
	}, nil
}

func (output Output) ToBytes() []byte {
	ret := []byte{}

	ret = append(ret, output.AssetID...)
	ret = append(ret, output.Amount...)
	ret = append(ret, output.Lock...)
	ret = append(ret, output.ProgramHash...)

	return ret
}
