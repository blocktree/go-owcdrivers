package polkadotTransaction

const (
	KSM_Balannce_Transfer = "0400"
	DOT_Balannce_Transfer = "050000"
	Balannce_Transfer_name = "transfer"
	Default_Period = 50
	SigningBitV4 = byte(0x84)
	Compact_U32 = "Compact<u32>"
	AccounntIDFollow = false
)

const  (
	modeBits = 2
	singleMode   byte = 0
	twoByteMode  byte = 1
	fourByteMode byte = 2
	bigIntMode   byte = 3
	singleModeMaxValue   = 63
	twoByteModeMaxValue  = 16383
	fourByteModeMaxValue = 1073741823
)
var modeToNumOfBytes = map[byte]uint{
	singleMode:   1,
	twoByteMode:  2,
	fourByteMode: 4,
}