package filenetTransaction

import (
	"encoding/hex"
	"errors"
)

func decodeAddress(address string) ([]byte, error) {

	hexBytes, err := Decode(address, BitcoinAlphabet)
	if err != nil {
		return nil, errors.New("Invalid address!")
	}

	addrBytes, err := hex.DecodeString(string(hexBytes))
	if err != nil {
		return nil, errors.New("Invalid address!")
	}

	if len(addrBytes) != 20 {
		return nil, errors.New("Invalid address!")
	}

	return addrBytes, nil
}

func encodeAddress(hash []byte) (string, error) {

	if hash == nil || len(hash) != 20 {
		return "", errors.New("Miss hash data!")
	}

	return Encode([]byte(hex.EncodeToString(hash)), BitcoinAlphabet), nil
}
