package ontologyTransaction

type TxHash struct {
	Hash      string
	Addresses []string
}

func (tx TxHash) GetTxHashHex() string {
	return tx.Hash
}
