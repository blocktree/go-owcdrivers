package bigbangTransaction

import (
	"encoding/base32"
	"errors"
)

func addressDecode(address string) ([]byte, error) {
	if address[:1] != pubkeyPrefix {
		return nil, errors.New("Invalid address, only public key address supported!")
	}

	pubkey, err := base32.NewEncoding(alphaBet).DecodeString(address[1:])

	if err != nil || len(pubkey) != 32 + 3 {
		return nil, errors.New("Invalid address!")
	}

	chkBytes := uint32ToBigEndianBytes(crc24q(pubkey[:32]))[1:]
	for i := 0; i < 3; i ++ {
		if chkBytes[i] != pubkey[32 + i] {
			return nil, errors.New("Invalid address with bad checksum!")
		}
	}

	return append([]byte{byte(pubkeyPrefix[0] - '0')}, pubkey[:32]...), nil
}
