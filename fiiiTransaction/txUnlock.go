package fiiiTransaction

import (
	"encoding/hex"
	"errors"
	"strings"
)

const libraryPrefix = "302A300506032B6570032100"

type SigPub struct {
	Signature []byte
	Pubkey    []byte
}

func (sp SigPub) GenUnlockScript() (string, error) {

	if sp.Signature == nil || len(sp.Signature) != 64 {
		return "", errors.New("Invalid signature data!")
	}
	if sp.Pubkey == nil || len(sp.Pubkey) != 32 {
		return "", errors.New("Invalid public key data!")
	}

	return strings.ToUpper(hex.EncodeToString(sp.Signature)) + "[ALL] " + libraryPrefix + strings.ToUpper(hex.EncodeToString(sp.Pubkey)), nil
}
