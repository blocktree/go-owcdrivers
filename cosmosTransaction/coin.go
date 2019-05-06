package cosmosTransaction

import (
	"math/big"
	"strconv"
)

type Int struct {
	i *big.Int
}

type Coin struct {
	Amount string `json:"amount"`
	Denom  string `json:"denom"`
}
type Coins []Coin

func NewInt(n int64) Int {
	return Int{big.NewInt(n)}
}

func NewIntFromBigInt(i *big.Int) Int {
	if i.BitLen() > 255 {
		panic("NewIntFromBigInt() out of bound")
	}
	return Int{i}
}

func lt(i *big.Int, i2 *big.Int) bool { return i.Cmp(i2) == -1 }

func (i Int) LT(i2 Int) bool {
	return lt(i.i, i2.i)
}

func ZeroInt() Int { return Int{big.NewInt(0)} }

func NewCoin(denom string, amount int64) Coin {

	if amount == 0 {
		return Coin{}
	}

	return Coin{
		Denom:  denom,
		Amount: strconv.FormatInt(amount, 10),
	}
}
