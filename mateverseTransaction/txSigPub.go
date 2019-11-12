package mateverseTransaction

import (
	"encoding/hex"
	"github.com/blocktree/go-owcrypt"
)

type SignaturePubkey struct {
	Signature []byte
	Pubkey    []byte
}

func (sp SignaturePubkey) encodeSignatureToScript(sigType byte) []byte {
	r := sp.Signature[:32]
	s := sp.Signature[32:]
	if r[0]&0x80 == 0x80 {
		r = append([]byte{0x00}, r...)
	} else {
		for i := 0; i < 32; i++ {
			if r[0] == 0 && r[1]&0x80 != 0x80 {
				r = r[1:]
			} else {
				break
			}
		}
	}
	if s[0]&0x80 == 0x80 {
		s = append([]byte{0}, s...)
	} else {
		for i := 0; i < 32; i++ {
			if s[0] == 0 && s[1]&0x80 != 0x80 {
				s = s[1:]
			} else {
				break
			}
		}
	}

	r = append([]byte{byte(len(r))}, r...)
	r = append([]byte{0x02}, r...)
	s = append([]byte{byte(len(s))}, s...)
	s = append([]byte{0x02}, s...)

	rs := append(r, s...)
	rs = append([]byte{byte(len(rs))}, rs...)
	rs = append(rs, sigType)
	rs = append([]byte{0x30}, rs...)
	rs = append([]byte{byte(len(rs))}, rs...)

	return rs
}
func (sp SignaturePubkey) encodeToScript(sigType byte) []byte {

	ret :=  append(sp.encodeSignatureToScript(sigType), append([]byte{byte(len(sp.Pubkey))}, sp.Pubkey...)...)
	return append([]byte{byte(len(ret))}, ret...)
}


func verifyTransactionHash(pubkey, hash, signature string) bool {
	pubBytes, err := hex.DecodeString(pubkey)
	if err != nil || len(pubBytes) != 33 {
		return false
	}

	hashBytes, err := hex.DecodeString(hash)
	if err != nil || len(hashBytes) != 32 {
		return false
	}

	sigBytes, err := hex.DecodeString(signature)
	if err != nil || len(sigBytes) != 64 {
		return false
	}

	pubBytes = owcrypt.PointDecompress(pubBytes, owcrypt.ECC_CURVE_SECP256K1)[1:]
	if owcrypt.SUCCESS != owcrypt.Verify(pubBytes, nil, 0, hashBytes, 32, sigBytes, owcrypt.ECC_CURVE_SECP256K1) {
		return false
	}

	return true
}
