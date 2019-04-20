package addressEncoder

import (
	"strings"
)

const (
	AEPrefixAccountPubkey = "ak_"
)

func decodeAE(pubKey string, addresstype AddressType) ([]byte, error) {

	var pubKeyMaterial string
	if strings.HasPrefix(pubKey, AEPrefixAccountPubkey) {
		pubKeyMaterial = pubKey[len(AEPrefixAccountPubkey):]
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

func encodeAE(hash []byte, addresstype AddressType) string {
	addresstype.EncodeType = "base58"
	data := catData(hash, calcChecksum(hash, addresstype.ChecksumType))
	return string(addresstype.Prefix) + encodeData(data, "base58", addresstype.Alphabet)
}
