package ontologyTransaction

import (
	"errors"
	"math/big"

	"github.com/blocktree/go-owcrypt"
)

type SigPub struct {
	Signature []byte
	PublicKey []byte
}

func serilizeS(sig []byte) []byte {
	s := sig[32:]
	numS := new(big.Int).SetBytes(s)
	numHalfOrder := new(big.Int).SetBytes(HalfCurveOrder)
	if numS.Cmp(numHalfOrder) > 0 {
		numOrder := new(big.Int).SetBytes(CurveOrder)
		numS.Sub(numOrder, numS)

		s = numS.Bytes()
		if len(s) < 32 {
			for i := 0; i < 32-len(s); i++ {
				s = append([]byte{0x00}, s...)
			}
		}
		return append(sig[:32], s...)
	}
	return sig
}

func calcSignaturePubkey(txHash, prikey []byte) (*SigPub, error) {
	if txHash == nil || len(txHash) != 32 || prikey == nil || len(prikey) != 32 {
		return nil, errors.New("Transaction hash or private key data error!")
	}

	sig, err := owcrypt.Signature(prikey, nil, 0, txHash, 32, owcrypt.ECC_CURVE_SECP256R1)
	if err != owcrypt.SUCCESS {
		return nil, errors.New("Signature failed!")
	}
	sig = serilizeS(sig)

	pub, err := owcrypt.GenPubkey(prikey, owcrypt.ECC_CURVE_SECP256R1)
	if err != owcrypt.SUCCESS {
		return nil, errors.New("Get Pubkey failed!")
	}
	pub = owcrypt.PointCompress(pub, owcrypt.ECC_CURVE_SECP256R1)

	return &SigPub{sig, pub}, nil
}

func (sp SigPub) toBytes() []byte {
	ret := []byte{}

	ret = append(ret, byte(len(sp.Signature)))
	ret = append(ret, sp.Signature...)
	ret = append([]byte{byte(len(ret))}, ret...)

	pub := []byte{}
	pub = append(pub, byte(len(sp.PublicKey)))
	pub = append(pub, sp.PublicKey...)
	pub = append(pub, OpCodeCheckSig)
	pub = append([]byte{byte(len(pub))}, pub...)

	ret = append(ret, pub...)
	//ret = append([]byte{0x01}, ret...)
	return ret
}

func decodeSigPubBytes(sp []byte) (*SigPub, error) {
	var ret SigPub
	limit := len(sp)
	index := 0

	// if index+1 > limit {
	// 	return nil, errors.New("Invalid signature & public key data!")
	// }
	// if sp[index] != 0x01 {
	// 	return nil, errors.New("Invalid signature & public key data!")
	// }
	// index++

	if index+2 > limit {
		return nil, errors.New("Invalid signature & public key data!")
	}
	if sp[index] != 0x41 || sp[index+1] != 0x40 {
		return nil, errors.New("Invalid signature & public key data!")
	}
	index += 2

	if index+64 > limit {
		return nil, errors.New("Invalid signature & public key data!")
	}

	ret.Signature = sp[index : index+64]
	index += 64

	if index+2 > limit {
		return nil, errors.New("Invalid signature & public key data!")
	}
	if sp[index] != 0x23 || sp[index+1] != 0x21 {
		return nil, errors.New("Invalid signature & public key data!")
	}
	index += 2

	ret.PublicKey = sp[index : index+33]
	index += 33

	if index+1 != limit {
		return nil, errors.New("Invalid signature & public key data!")
	}

	if sp[index] != OpCodeCheckSig {
		return nil, errors.New("Invalid signature & public key data!")
	}
	return &ret, nil
}
