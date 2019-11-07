package waykichainTransaction

const (
	AddressPrefix        = byte(0x49)
	AddressPrefixTestNet = byte(0x87)
	Version              = int64(0x01)
	TxType_REWARD        = byte(0x01)
	TxType_REGACCT       = byte(0x02)
	TxType_COMMON        = byte(0x03)
	TxType_CONTRACT      = byte(0x04)
	TxType_UcoinTransfer = byte(0x0B)

	DefaultFeeSymbol     = "WICC"
)
