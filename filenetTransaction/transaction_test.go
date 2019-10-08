package filenetTransaction

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestTrans(t *testing.T) {
	in := Vin{Address:"3YZ92rqUpjYzXDrkL41Fz89LUMYRysktyWkayNcqBnrfBXwW1mCN9QL"}
	
	out1 := Vout{
		Address: "3YZ92rqUpjYzXDrkL41Fz89LUMYRysktyWkayNcqBnrfBXwW1mCN9QL",
		Amount:  1000000000,
	}

	out2 := Vout{
		Address: "3YZ92rqUpjYzXDrkL41Fz89LUMYRysktyWkayNcqBnrfBXwW1mCN9QL",
		Amount:  2000000000,
	}

	outs := make(Vouts, 2)
	outs[0] = out1
	outs[1] = out2

	emptyTrans, hash, err := CreateEmptyTransactionAndHash(in, outs)
	if err != nil {
		t.Error(err)
		return
	} else {
		fmt.Println("empty : ", emptyTrans)
		fmt.Println("hash  : ", hash)
	}

	prikey, _ := hex.DecodeString("80bc398d7c4a674daa977566c2e6cd5040520027e57fe806dfaa868df4cc43ab")

	signature, err := SignTransaction(hash, prikey)
	if err != nil {
		t.Error(err)
		return
	} else {
		//when time stamp => 	trans.TimeStamp = uint64ToLittleEndianBytes(1569831542)
		//signature = "fd443a533ac614edf03c1de61c28f8c438b22dc9b76ab3686ac6dcd7f11eff58114b1bed4a0859302552ad146d8ea6c1171c0a2784af4c1ff061beaba19aacc5"
		fmt.Println("sig  : ", signature)
	}
	pubkey := "0226e56601a74eff3a96db55f940f8924ad9b54f86f8ea6205c22994bd599184ab"

	signedTrans, pass := VerifyAndCombineTransaction(emptyTrans, signature, pubkey)

	if pass {
		fmt.Println("signed : ", signedTrans)
	} else {
		t.Error("Failed!")
	}

}