package bytomTransaction

const (
	Bech32HRPSegwit           = "bm"
	HashPrefixEntry           = "entryid:"
	HashPrefixOutput          = "output1:"
	HashPrefixSpend           = "spend1:"
	HashPrefixMux             = "mux1:"
	HashPrefixTxheader        = "txheader:"
	DefaultWitnessVersion     = byte(0)
	DefaultSerFlags           = byte(7)
	DefaultTransactionVersion = uint64(1)
	DefaultAssetVersion       = byte(1)
	DefaultOutVersion         = byte(1)
	DefaultVMVersion          = uint64(1)
	Op_true                   = byte(0x51)
	Op_1                      = byte(0x51)
	Op_TxSignHash             = byte(0xAE)
	Op_CheckMultiSig          = byte(0xAD)

	BTMAssetID = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
)
