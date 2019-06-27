package omniTransaction

type AddressPrefix struct {
	P2PKHPrefix  []byte
	P2WPKHPrefix []byte
	Bech32Prefix string
}

var (
	BTCMainnetAddressPrefix = AddressPrefix{[]byte{0x00}, []byte{0x05}, "bc"}
	BTCTestnetAddressPrefix = AddressPrefix{[]byte{0x6F}, []byte{0xC4}, "tb"}
)

// Omni transaction type
const (
	SimpleSend             = 0
	SendAll                = 4
	DExAccept              = 22
	MetaDExCancelEcosystem = 28
	CloseCrowdsale         = 53
	Grant                  = 55
	Revoke                 = 56
	ChangeIssuer           = 70
	EnableFreezing         = 71
	DisableFreezing        = 72
	FreezeTokens           = 185
	UnfreezeTokens         = 186
)

// propertyID for USDT
const (
	MainTetherUS_01 = uint32(31)
	MainTetherUS_02 = uint32(192)
	MainTetherUS_03 = uint32(330)
	MainTetherUS_04 = uint32(341)
	MainTetherUS_05 = uint32(396)
	MainTetherUS_06 = uint32(397)
	MainTetherUS_07 = uint32(398)
	MainTetherUS_08 = uint32(399)
	MainTetherUS_09 = uint32(404)

	TestTetherUS_01 = uint32(2147484026)
	TestTetherUS_02 = uint32(2147484061)
	TestTetherUS_03 = uint32(2147484062)

	DefaultTetherUSID = TestTetherUS_01
)

// ecosystem defination for send all payload
const (
	EcoSystemMain = byte(1)
	EcoSystemTest = byte(2)

	DefaultEcoSystem = EcoSystemTest
)

const (
	DefaultTxVersion     = uint32(2)
	DefaultHashType      = uint32(1)
	MaxScriptElementSize = 520
)

const (
	SequenceFinal        = uint32(0xFFFFFFFF)
	SequenceMaxBip125RBF = uint32(0xFFFFFFFD)
)

const (
	SegWitSymbol  = byte(0)
	SegWitVersion = byte(1)
	SigHashAll    = byte(1)
)

const (
	OpCodeHash160     = byte(0xA9)
	OpCodeEqual       = byte(0x87)
	OpCodeEqualVerify = byte(0x88)
	OpCodeCheckSig    = byte(0xAC)
	OpCodeDup         = byte(0x76)
	OpCode_1          = byte(0x51)
	OpCheckMultiSig   = byte(0xAE)
	OpPushData1       = byte(0x4C)
	OpPushData2       = byte(0x4D)
	OpPushData3       = byte(0x4E)
	OpReturn          = byte(0x6A)
)

var (
	OmniPrefix     = [4]byte{0x6F, 0x6D, 0x6E, 0x69}
	CurveOrder     = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41}
	HalfCurveOrder = []byte{0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0}
)
