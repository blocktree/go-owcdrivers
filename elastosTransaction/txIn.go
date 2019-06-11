package elastosTransaction

import "errors"

type Input struct {
	TxID     []byte
	Vout     []byte
	Sequence []byte
}

func (in Vin) NewInput() (*Input, error) {
	txidBytes, err := reverseHexToBytes(in.TxID)
	if err != nil {
		return nil, errors.New("Invalid previous transaction ID!")
	}
	vout := uint16ToLittleEndianBytes(in.Vout)

	return &Input{
		TxID:     txidBytes,
		Vout:     vout,
		Sequence: []byte{0xff, 0xff, 0xff, 0xff},
	}, nil
}

func (input Input) ToBytes() []byte {

	ret := []byte{}

	ret = append(ret, input.TxID...)
	ret = append(ret, input.Vout...)
	ret = append(ret, input.Sequence...)

	return ret
}
