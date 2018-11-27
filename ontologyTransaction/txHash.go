package ontologyTransaction

type NormalTx struct {
	Address string
	SigType byte
	SigPub  SigPub
}

type MultiTx struct {
	Pubkey  string
	SigType byte
	SigPub  SigPub
}

type TxHash struct {
	Hash      string
	NRequired byte
	Normal    *NormalTx
	Multi     []MultiTx
}

func (tx TxHash) IsMultisig() bool {
	if tx.NRequired == 0 {
		return false
	}
	return true
}

func (tx TxHash) GetTxHashHex() string {
	return tx.Hash
}

func (tx TxHash) GetNormalTxAddress() string {
	return tx.Normal.Address
}
