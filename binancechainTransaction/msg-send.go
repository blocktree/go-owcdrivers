package binancechainTransaction

import (
	"github.com/binance-chain/go-sdk/common/bech32"
	ctypes "github.com/binance-chain/go-sdk/common/types"
	"github.com/binance-chain/go-sdk/types/msg"
	"github.com/pkg/errors"
)

func CreateSendMsg(fromAddress, toAddress, denom string, amount int64) (*msg.SendMsg, error) {
	prefix, from, err := bech32.DecodeAndConvert(fromAddress)
	if err != nil {
		return nil, err
	}

	if prefix != Bech32Prefix {
		return nil, errors.New("Invalid address!")
	}

	prefix, to, err := bech32.DecodeAndConvert(toAddress)
	if err != nil {
		return nil, err
	}

	if prefix != Bech32Prefix {
		return nil, errors.New("Invalid address!")
	}

	coin := ctypes.Coin{
		Denom:denom,
		Amount:amount,
	}

	transfer := msg.Transfer{
		ToAddr:to,
		Coins:ctypes.Coins{coin},
	}

	sendMsg := msg.CreateSendMsg(from, ctypes.Coins{coin},[]msg.Transfer{transfer})

	return &sendMsg, nil
}