package owkeychain

import (
	"errors"
	"strings"
)

var ChainPrefix = []byte{0x08, 0x61, 0x24, 0x96, 0x12, 0xae, 0x5c}

type MultiSigShare struct {
	Pubkey    []byte
	ChainCode []byte
	CurveType uint32
}

func (ms MultiSigShare) ChianEncode() string {
	data := make([]byte, 0)
	data = append(data, ChainPrefix...)
	if len(ms.Pubkey) == 32 {
		data = append(data, 0x00)
	}

	data = append(data, ms.Pubkey...)
	data = append(data, ms.ChainCode...)
	data = append(data, uint32ToBytes(ms.CurveType)...)

	return Encode(data, BitcoinAlphabet)
}

func ChainDecode(owchain string) (*MultiSigShare, error) {
	if strings.Index(owchain, "owchain") != 0 {
		return nil, errors.New("Invalid owchain encoded data!")
	}

	chainBytes, err := Decode(owchain, BitcoinAlphabet)
	if err != nil {
		return nil, err
	}

	if len(chainBytes) != 76 {
		return nil, errors.New("Invalid owchain encoded data length!")
	}

	for i, v := range ChainPrefix {
		if v != chainBytes[i] {
			return nil, errors.New("Invalid owchian prefix data!")
		}
	}
	pubkey := chainBytes[7:40]
	if pubkey[0] == 0x00 {
		pubkey = pubkey[1:]
	}
	return &MultiSigShare{
		Pubkey:    pubkey,
		ChainCode: chainBytes[40:72],
		CurveType: bytesToUInt32(chainBytes[72:]),
	}, nil
}

func GetMultiSigShareData(owpub string) (string, error) {
	pubParent, err := OWDecode(owpub)
	if err != nil {
		return "", err
	}

	if pubParent.isPrivate {
		pubParent = pubParent.GetPublicKey()
	}

	var ms MultiSigShare

	ms.Pubkey = pubParent.key
	ms.ChainCode = pubParent.chainCode
	ms.CurveType = pubParent.curveType

	return ms.ChianEncode(), nil
}
