package eosSignature

import (
	"errors"

	owcrypt "github.com/blocktree/go-owcrypt"
)

func signRFC6979(privateKey, hash []byte, nonce int) ([]byte, error) {
	k := generateRandomFromNonce(privateKey, hash, nonce)

	if owcrypt.PreprocessRandomNum(k) != owcrypt.SUCCESS {
		return nil, errors.New("Failed to set random!")
	}
	sig, ret := owcrypt.Signature(privateKey, nil, 0, hash, 32, owcrypt.ECC_CURVE_SECP256K1|owcrypt.NOUNCE_OUTSIDE_FLAG)
	if ret != owcrypt.SUCCESS {
		return nil, errors.New("Failed to signature!")
	}
	return sig, nil
}

func equals(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for index := 0; index < len(a); index++ {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

func makeCompact(sig, publicKey, hash []byte) ([]byte, error) {
	for i := 0; i < 2; i++ {
		tmp := append(sig, byte(i))
		pk, ret := owcrypt.RecoverPubkey(tmp, hash, owcrypt.ECC_CURVE_SECP256K1)
		if ret == owcrypt.SUCCESS && equals(pk, publicKey) {
			result := make([]byte, 1, 2*32+1)
			result[0] = 27 + byte(i)
			result[0] += 4
			// Not sure this needs rounding but safer to do so.
			curvelen := (256 + 7) / 8

			// Pad R and S to curvelen if needed.
			bytelen := (256 + 7) / 8
			if bytelen < curvelen {
				result = append(result,
					make([]byte, curvelen-bytelen)...)
			}
			result = append(result, sig[:32]...)

			bytelen = (256 + 7) / 8
			if bytelen < curvelen {
				result = append(result,
					make([]byte, curvelen-bytelen)...)
			}
			result = append(result, sig[32:]...)

			return result, nil
		}
	}

	return nil, errors.New("no valid solution for pubkey found")
}

func isCanonical(compactSig []byte) bool {
	d := compactSig
	t1 := (d[1] & 0x80) == 0
	t2 := !(d[1] == 0 && ((d[2] & 0x80) == 0))
	t3 := (d[33] & 0x80) == 0
	t4 := !(d[33] == 0 && ((d[34] & 0x80) == 0))
	return t1 && t2 && t3 && t4
}

func SignCanonical(privateKey, hash []byte) ([]byte, error) {

	for i := 0; i < 25; i++ {
		sig, err := signRFC6979(privateKey, hash, i)
		if err != nil {
			return nil, err
		}

		publicKey, ret := owcrypt.GenPubkey(privateKey, owcrypt.ECC_CURVE_SECP256K1)
		if ret != owcrypt.SUCCESS {
			return nil, errors.New("Invalid private key!")
		}
		compactSig, err := makeCompact(sig, publicKey, hash)
		if err != nil {
			continue
		}

		if isCanonical(compactSig) {
			return compactSig, nil
		}
	}
	return nil, errors.New("couldn't find a canonical signature")
}
