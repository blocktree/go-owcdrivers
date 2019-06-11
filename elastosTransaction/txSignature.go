package elastosTransaction

import "errors"

type SigPub struct {
	PublicKey []byte
	Signature []byte
}

type Sigpubs []SigPub

func (sp SigPub) ToBytes() ([]byte, error) {

	if sp.PublicKey == nil || len(sp.PublicKey) != 0x21 {
		return nil, errors.New("Miss public key!")
	}

	if sp.Signature == nil || len(sp.Signature) != 0x40 {
		return nil, errors.New("Miss signature data!")
	}

	ret := []byte{}
	ret = append(ret, 0x41, 0x40)
	ret = append(ret, sp.Signature...)
	ret = append(ret, 0x23, 0x21)
	ret = append(ret, sp.PublicKey...)
	ret = append(ret, OP_CHECKSIG)

	return ret, nil
}

func (sps Sigpubs) ToBytes() ([]byte, error) {
	ret := []byte{}

	ret = append(ret, uint64ToUvarint(uint64(len(sps)))...)
	for _, sp := range sps {
		data, err := sp.ToBytes()
		if err != nil {
			return nil, err
		}
		ret = append(ret, data...)
	}
	return ret, nil
}
