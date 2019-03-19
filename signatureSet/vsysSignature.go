package signatureSet

import (
	owcrypt "github.com/blocktree/go-owcrypt"
)

func VSYSSignature(prikey, msg []byte) ([]byte, uint16) {
	return owcrypt.Signature(prikey, nil, 0, msg, uint16(len(msg)), owcrypt.ECC_CURVE_X25519)
}
