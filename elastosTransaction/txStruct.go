package elastosTransaction

import owcrypt "github.com/blocktree/go-owcrypt"

type Transaction struct {
	TxType         byte
	PayloadVersion byte
	Attributes     []*[]byte
	Inputs         []*Input
	Outputs        []*Output
	LockTime       []byte
	Signatures     []*SigPub
}

func NewTransaction(vins []Vin, vouts []Vout) (*Transaction, error) {
	tx := Transaction{}

	tx.TxType = TxTypeTransferAsset
	tx.PayloadVersion = DefaultPayloadVersion
	tx.Attributes = nil

	for _, in := range vins {
		input, err := in.NewInput()
		if err != nil {
			return nil, err
		}
		tx.Inputs = append(tx.Inputs, input)
	}

	for _, out := range vouts {
		output, err := out.NewOutput()
		if err != nil {
			return nil, err
		}
		tx.Outputs = append(tx.Outputs, output)
	}

	tx.LockTime = []byte{0, 0, 0, 0}

	tx.Signatures = nil

	return &tx, nil
}

func (tx Transaction) GetEmptyAndHash() ([]byte, []byte) {
	txBytes := []byte{}

	txBytes = append(txBytes, tx.TxType, tx.PayloadVersion, 0x00) // 0x00 for attributes count

	txBytes = append(txBytes, uint64ToUvarint(uint64(len(tx.Inputs)))...) // input count

	for _, input := range tx.Inputs {
		txBytes = append(txBytes, input.ToBytes()...)
	}

	txBytes = append(txBytes, uint64ToUvarint(uint64(len(tx.Outputs)))...) // output count
	for _, output := range tx.Outputs {
		txBytes = append(txBytes, output.ToBytes()...)
	}

	txBytes = append(txBytes, tx.LockTime...)

	return txBytes, owcrypt.Hash(txBytes, 0, owcrypt.HASH_ALG_SHA256)
}
