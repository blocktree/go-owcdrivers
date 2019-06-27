package waykichainTransaction

const (
	AddressPrefix   = byte(0x49)
	Version         = int64(0x01)
	TxType_REWARD   = byte(0x01)
	TxType_REGACCT  = byte(0x02)
	TxType_COMMON   = byte(0x03)
	TxType_CONTRACT = byte(0x04)
)
