package eosSignature

import (
	"bytes"
	"crypto/sha256"
	"math/big"

	owcrypt "github.com/blocktree/go-owcrypt"
)

func int2octets(v *big.Int, rolen int) []byte {
	out := v.Bytes()

	// left pad with zeros if it's too short
	if len(out) < rolen {
		out2 := make([]byte, rolen)
		copy(out2[rolen-len(out):], out)
		return out2
	}

	// drop most significant bytes if it's too long
	if len(out) > rolen {
		out2 := make([]byte, rolen)
		copy(out2, out[len(out)-rolen:])
		return out2
	}

	return out
}

func hashToInt(hash []byte) *big.Int {
	orderBits := new(big.Int).SetBytes(owcrypt.GetCurveOrder(owcrypt.ECC_CURVE_SECP256K1)).BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

func bits2octets(in []byte, rolen int) []byte {
	z1 := hashToInt(in)
	z2 := new(big.Int).Sub(z1, new(big.Int).SetBytes(owcrypt.GetCurveOrder(owcrypt.ECC_CURVE_SECP256K1)))
	if z2.Sign() < 0 {
		return int2octets(z1, rolen)
	}
	return int2octets(z2, rolen)
}

func generateRandomFromNonce(privateKey, hash []byte, nonce int) []byte {
	privkey := new(big.Int).SetBytes(privateKey)
	if nonce > 0 {
		moreHash := sha256.New()
		moreHash.Write(hash)
		moreHash.Write(bytes.Repeat([]byte{0x00}, nonce))
		hash = moreHash.Sum(nil)
	}

	q := new(big.Int).SetBytes(owcrypt.GetCurveOrder(owcrypt.ECC_CURVE_SECP256K1))
	x := privkey

	qlen := q.BitLen()
	holen := 32
	rolen := (qlen + 7) >> 3
	bx := append(int2octets(x, rolen), bits2octets(hash, rolen)...)

	// Step B
	v := bytes.Repeat([]byte{0x01}, holen)

	// Step C (Go zeroes the all allocated memory)
	k := make([]byte, holen)

	// Step D
	k = owcrypt.Hmac(k, append(append(v, 0x00), bx...), owcrypt.HMAC_SHA256_ALG)

	// Step E
	v = owcrypt.Hmac(k, v, owcrypt.HMAC_SHA256_ALG)

	// Step F
	k = owcrypt.Hmac(k, append(append(v, 0x01), bx...), owcrypt.HMAC_SHA256_ALG)

	// Step G
	v = owcrypt.Hmac(k, v, owcrypt.HMAC_SHA256_ALG)

	// Step H
	for {
		// Step H1
		var t []byte

		// Step H2
		for len(t)*8 < qlen {
			v = owcrypt.Hmac(k, v, owcrypt.HMAC_SHA256_ALG)
			t = append(t, v...)
		}

		// Step H3
		secret := hashToInt(t)
		if secret.Cmp(big.NewInt(1)) >= 0 && secret.Cmp(q) < 0 {
			return secret.Bytes()
		}
		k = owcrypt.Hmac(k, append(v, 0x00), owcrypt.HMAC_SHA256_ALG)
		v = owcrypt.Hmac(k, v, owcrypt.HMAC_SHA256_ALG)
	}
}
