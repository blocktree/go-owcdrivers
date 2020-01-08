package bytomTransaction

import (
	"errors"

	"github.com/blocktree/go-owcrypt"
)

type SigPub struct {
	Signature []byte
	Pubkey    []byte
}

func (sp *SigPub) toBytes() ([]byte, error) {
	if sp == nil || sp.Signature == nil || sp.Pubkey == nil {
		return nil, errors.New("Miss signature or public key data!")
	}

	if len(sp.Signature) != 64 || len(sp.Pubkey) != 32 {
		return nil, errors.New("Invalid signature or public key data!")
	}

	var ret []byte

	ret = append(ret, 0x63, 0x02, 0x40)
	ret = append(ret, sp.Signature...)
	ret = append(ret, 0x20)
	ret = append(ret, sp.Pubkey...)

	return ret, nil
}

func calcSignaturePubkey(hash, prikey []byte) (*SigPub, error) {
	var sp SigPub
	if hash == nil || len(hash) != 32 || prikey == nil || len(prikey) != 32 {
		return nil, errors.New("Miss transaction hash or prikey data!")
	}

	sig,_, err := owcrypt.Signature(prikey, nil, hash, owcrypt.ECC_CURVE_ED25519)

	if err != owcrypt.SUCCESS {
		return nil, errors.New("sign error!")
	}

	sp.Signature = sig

	pub := owcrypt.Point_mulBaseG(prikey, owcrypt.ECC_CURVE_ED25519)

	sp.Pubkey = pub

	return &sp, nil
}
