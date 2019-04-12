package addressEncoder

import (
	"fmt"
	"strings"
)

const (
	EOSPublicKeyPrefix       = "PUB_"
	EOSPublicKeyK1Prefix     = "PUB_K1_"
	EOSPublicKeyR1Prefix     = "PUB_R1_"
	EOSPublicKeyPrefixCompat = "EOS"
)

func decodeEOS(pubKey string, addresstype AddressType) ([]byte, error) {

	var pubKeyMaterial string
	if strings.HasPrefix(pubKey, EOSPublicKeyR1Prefix) {
		pubKeyMaterial = pubKey[len(EOSPublicKeyR1Prefix):] // strip "PUB_R1_"
	} else if strings.HasPrefix(pubKey, EOSPublicKeyK1Prefix) {
		pubKeyMaterial = pubKey[len(EOSPublicKeyK1Prefix):] // strip "PUB_K1_"
	} else if strings.HasPrefix(pubKey, EOSPublicKeyPrefixCompat) { // "EOS"
		pubKeyMaterial = pubKey[len(EOSPublicKeyPrefixCompat):] // strip "EOS"
	} else {
		return nil, fmt.Errorf("public key should start with [%q | %q] (or the old %q)", EOSPublicKeyK1Prefix, EOSPublicKeyR1Prefix, EOSPublicKeyPrefixCompat)
	}

	ret, err := Base58Decode(pubKeyMaterial, NewBase58Alphabet(addresstype.Alphabet))
	if err != nil {
		return nil, ErrorInvalidAddress
	}
	if verifyChecksum(ret, addresstype.ChecksumType) == false {
		return nil, ErrorInvalidAddress
	}

	return ret[:len(ret)-4], nil
}

func encodeEOS(hash []byte, addresstype AddressType) string {
	addresstype.EncodeType = "base58"
	data := catData(hash, calcChecksum(hash, addresstype.ChecksumType))
	return string(addresstype.Prefix) + encodeData(data, "base58", addresstype.Alphabet)
}