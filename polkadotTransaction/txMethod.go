package polkadotTransaction

import (
	"encoding/hex"
	"errors"
)

type MethodTransfer struct {
	DestPubkey []byte
	Amount     []byte
}

func NewMethodTransfer(pubkey string, amount uint64) (*MethodTransfer, error) {
	pubBytes, err := hex.DecodeString(pubkey)
	if  err != nil || len(pubBytes) != 32 {
		return nil, errors.New("invalid dest public key")
	}

	if amount == 0 {
		return nil, errors.New("zero amount")
	}
	amountStr:= Encode( uint64(amount))
	if err != nil {
		return nil, errors.New("invalid amount")
	}

	amountBytes, _ := hex.DecodeString(amountStr)

	return &MethodTransfer{
		DestPubkey: pubBytes,
		Amount:     amountBytes,
	}, nil
}

func (mt MethodTransfer) ToBytes(transferCode string) ([]byte, error) {

	if mt.DestPubkey == nil || len(mt.DestPubkey) != 32 || mt.Amount == nil || len(mt.Amount) == 0 {
		return nil, errors.New("invalid method")
	}

	ret, _ := hex.DecodeString(transferCode)
	if AccounntIDFollow {
		ret = append(ret, 0xff)
	}

	ret = append(ret, mt.DestPubkey...)
	ret = append(ret, mt.Amount...)

	return ret, nil
}