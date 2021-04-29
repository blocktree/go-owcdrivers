package addressEncoder

var (
	BTCAlphabet        = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	XMRAlphabet        = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	OntAlphabet        = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	XRPAlphabet        = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
	ZECAlphabet        = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	BTCBech32Alphabet  = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	BTMBech32Alphabet  = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	LTCAlphabet        = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	LTCBech32Alphabet  = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	BCHLegacyAlphabet  = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	BCHCashAlphabet    = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	XTZAlphabet        = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	HCAlphabet         = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	QTUMAlphabet       = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	DCRDAlphabet       = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	NASAlphabet        = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	TRONAlphabet       = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	VSYSAlphabet       = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	ATOMBech32Alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	XCHBech32Alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
)

type AddressType struct {
	EncodeType   string //编码类型
	Alphabet     string //码表
	ChecksumType string //checksum类型(Prefix string when encode type is base32PolyMod)
	HashType     string //地址hash类型，传入数据为公钥时起效
	HashLen      int    //编码前的数据长度
	Prefix       []byte //数据前面的填充
	Suffix       []byte //数据后面的填充
}

//func (at *AddressType) Prefix() []byte {
//	return at.Prefix
//}

var (
	//BTC stuff
	BTC_mainnetAddressP2PKH         = AddressType{"base58", BTCAlphabet, "doubleSHA256", "h160", 20, []byte{0x00}, nil}
	BTC_mainnetAddressP2SH          = AddressType{"base58", BTCAlphabet, "doubleSHA256", "h160", 20, []byte{0x05}, nil}
	BTC_mainnetAddressBech32V0      = AddressType{"bech32", BTCBech32Alphabet, "bc", "h160", 20, []byte{0}, nil}
	BTC_mainnetPrivateWIF           = AddressType{"base58", BTCAlphabet, "doubleSHA256", "", 32, []byte{0x80}, nil}
	BTC_mainnetPrivateWIFCompressed = AddressType{"base58", BTCAlphabet, "doubleSHA256", "", 32, []byte{0x80}, []byte{0x01}}
	BTC_mainnetPublicBIP32          = AddressType{"base58", BTCAlphabet, "doubleSHA256", "", 74, []byte{0x04, 0x88, 0xB2, 0x1E}, nil}
	BTC_mainnetPrivateBIP32         = AddressType{"base58", BTCAlphabet, "doubleSHA256", "", 74, []byte{0x04, 0x88, 0xAD, 0xE4}, nil}
	BTC_testnetAddressP2PKH         = AddressType{"base58", BTCAlphabet, "doubleSHA256", "h160", 20, []byte{0x6F}, nil}
	BTC_testnetAddressP2SH          = AddressType{"base58", BTCAlphabet, "doubleSHA256", "h160", 20, []byte{0xC4}, nil}
	BTC_testnetAddressBech32V0      = AddressType{"bech32", BTCBech32Alphabet, "tb", "h160", 20, []byte{0}, nil}
	BTC_testnetPrivateWIF           = AddressType{"base58", BTCAlphabet, "doubleSHA256", "", 32, []byte{0xEF}, nil}
	BTC_testnetPrivateWIFCompressed = AddressType{"base58", BTCAlphabet, "doubleSHA256", "", 32, []byte{0xEF}, []byte{0x01}}
	BTC_testnetPublicBIP32          = AddressType{"base58", BTCAlphabet, "doubleSHA256", "", 74, []byte{0x04, 0x35, 0x87, 0xCF}, nil}
	BTC_testnetPrivateBIP32         = AddressType{"base58", BTCAlphabet, "doubleSHA256", "", 74, []byte{0x04, 0x35, 0x83, 0x94}, nil}

	//XMR stuff
	XMR_mainnetPublicAddress           = AddressType{"XMR", XMRAlphabet, "keccak256", "", 64, []byte{0x12}, nil}
	XMR_mainnetPublicSubAddress        = AddressType{"XMR", XMRAlphabet, "keccak256", "", 64, []byte{0x2A}, nil}
	XMR_mainnetPublicIntegratedAddress = AddressType{"XMR", XMRAlphabet, "keccak256", "payID", 72, []byte{0x13}, nil}
	XMR_testnetPublicAddress           = AddressType{"XMR", XMRAlphabet, "keccak256", "", 64, []byte{0x35}, nil}
	XMR_testnetPublicSubAddress        = AddressType{"XMR", XMRAlphabet, "keccak256", "", 64, []byte{0x3f}, nil}
	XMR_testnetPublicIntegratedAddress = AddressType{"XMR", XMRAlphabet, "keccak256", "payID", 72, []byte{0x36}, nil}

	//DOGE stuff
	//DOGE_singleSignAddressP2PKH = AddressType{"base58", BTCAlphabet, "doubleSHA256", "h160", 20, []byte{0x16}, nil}
	DOGE_multiSignAddressP2PKH = AddressType{"base58", BTCAlphabet, "doubleSHA256", "h160", 20, []byte{0x16}, nil}
	//ONT stuff
	ONT_Address = AddressType{"base58", OntAlphabet, "doubleSHA256", "h160", 20, []byte{0x17}, nil}
	//XRP stuff
	XRP_Address = AddressType{"base58", XRPAlphabet, "doubleSHA256", "h160", 20, []byte{0x00}, nil}
	//BTM stuff
	BTM_mainnetAddressBech32V0 = AddressType{"bech32", BTCBech32Alphabet, "bm", "h160", 20, []byte{0}, nil}
	BTM_testnetAddressBech32V0 = AddressType{"bech32", BTCBech32Alphabet, "tm", "h160", 20, []byte{0}, nil}
	//ZEC stuff
	ZEC_mainnet_t_AddressP2PKH = AddressType{"base58", ZECAlphabet, "doubleSHA256", "h160", 20, []byte{0x1C, 0xB8}, nil}
	ZEC_mainnet_t_AddressP2SH  = AddressType{"base58", ZECAlphabet, "doubleSHA256", "h160", 20, []byte{0x1C, 0xBD}, nil}
	ZEC_testnet_t_AddressP2PKH = AddressType{"base58", ZECAlphabet, "doubleSHA256", "h160", 20, []byte{0x1D, 0x25}, nil}
	ZEC_testnet_t_AddressP2SH  = AddressType{"base58", ZECAlphabet, "doubleSHA256", "h160", 20, []byte{0x1C, 0xBA}, nil}

	//LTC stuff
	LTC_mainnetAddressP2PKH         = AddressType{"base58", LTCAlphabet, "doubleSHA256", "h160", 20, []byte{0x30}, nil}
	LTC_mainnetAddressP2SH          = AddressType{"base58", LTCAlphabet, "doubleSHA256", "h160", 20, []byte{0x05}, nil}
	LTC_mainnetAddressP2SH2         = AddressType{"base58", LTCAlphabet, "doubleSHA256", "h160", 20, []byte{0x32}, nil}
	LTC_mainnetAddressBech32V0      = AddressType{"bech32", LTCBech32Alphabet, "ltc", "h160", 20, []byte{0}, nil}
	LTC_mainnetPrivateWIF           = AddressType{"base58", LTCAlphabet, "doubleSHA256", "", 32, []byte{0xB0}, nil}
	LTC_mainnetPrivateWIFCompressed = AddressType{"base58", LTCAlphabet, "doubleSHA256", "", 32, []byte{0xB0}, []byte{0x01}}
	LTC_mainnetPublicBIP32          = AddressType{"base58", BTCAlphabet, "doubleSHA256", "", 74, []byte{0x04, 0x88, 0xB2, 0x1E}, nil}
	LTC_mainnetPrivateBIP32         = AddressType{"base58", BTCAlphabet, "doubleSHA256", "", 74, []byte{0x04, 0x88, 0xAD, 0xE4}, nil}
	LTC_testnetAddressP2PKH         = AddressType{"base58", LTCAlphabet, "doubleSHA256", "h160", 20, []byte{0x6F}, nil}
	LTC_testnetAddressP2SH          = AddressType{"base58", LTCAlphabet, "doubleSHA256", "h160", 20, []byte{0xC4}, nil}
	LTC_testnetAddressP2SH2         = AddressType{"base58", LTCAlphabet, "doubleSHA256", "h160", 20, []byte{0x3A}, nil}
	LTC_testnetAddressBech32V0      = AddressType{"bech32", LTCBech32Alphabet, "tltc", "h160", 20, []byte{0}, nil}
	LTC_testnetPrivateWIF           = AddressType{"base58", LTCAlphabet, "doubleSHA256", "", 32, []byte{0xEF}, nil}
	LTC_testnetPrivateWIFCompressed = AddressType{"base58", LTCAlphabet, "doubleSHA256", "", 32, []byte{0xEF}, []byte{0x01}}
	LTC_testnetPublicBIP32          = AddressType{"base58", BTCAlphabet, "doubleSHA256", "", 74, []byte{0x04, 0x35, 0x87, 0xCF}, nil}
	LTC_testnetPrivateBIP32         = AddressType{"base58", BTCAlphabet, "doubleSHA256", "", 74, []byte{0x04, 0x35, 0x83, 0x94}, nil}

	//BCH stuff
	BCH_mainnetAddressLegacy = AddressType{"base58", BCHLegacyAlphabet, "doubleSHA256", "h160", 20, []byte{0x00}, nil}
	BCH_mainnetAddressCash   = AddressType{"base32PolyMod", BCHCashAlphabet, "bitcoincash", "h160", 21, nil, nil}

	//XTZ stuff
	XTZ_mainnetAddress_tz1   = AddressType{"base58", XTZAlphabet, "doubleSHA256", "blake2b160", 20, []byte{0x06, 0xA1, 0x9F}, nil}
	XTZ_mainnetAddress_tz2   = AddressType{"base58", XTZAlphabet, "doubleSHA256", "blake2b160", 20, []byte{0x06, 0xA1, 0xA1}, nil}
	XTZ_mainnetAddress_tz3   = AddressType{"base58", XTZAlphabet, "doubleSHA256", "blake2b160", 20, []byte{0x06, 0xA1, 0xA4}, nil}
	XTZ_mainnetPublic_edpk   = AddressType{"base58", XTZAlphabet, "doubleSHA256", "", 32, []byte{0x0D, 0x0F, 0x25, 0xD9}, nil}
	XTZ_mainnetPrivate_edsk  = AddressType{"base58", XTZAlphabet, "doubleSHA256", "", 64, []byte{0x0D, 0x0F, 0x3A, 0x07}, nil}
	XTZ_mainnetPrivate_edsk2 = AddressType{"base58", XTZAlphabet, "doubleSHA256", "", 32, []byte{0x2B, 0xF6, 0x4E, 0x07}, nil}
	XTZ_mainnetPrivate_spsk  = AddressType{"base58", XTZAlphabet, "doubleSHA256", "", 32, []byte{0x11, 0xA2, 0xE0, 0xC9}, nil}
	XTZ_mainnetPrivate_p2sk  = AddressType{"base58", XTZAlphabet, "doubleSHA256", "blake2b160", 32, []byte{0x10, 0x51, 0xEE, 0xBD}, nil}

	//ETH stuff
	ETH_mainnetPublicAddress = AddressType{"eip55", "", "", "keccak256", 32, nil, nil}

	//QTUM stuff
	QTUM_mainnetAddressP2PKH         = AddressType{"base58", QTUMAlphabet, "doubleSHA256", "h160", 20, []byte{0x3A}, nil}
	QTUM_mainnetAddressP2SH          = AddressType{"base58", QTUMAlphabet, "doubleSHA256", "h160", 20, []byte{0x32}, nil}
	QTUM_mainnetPrivateWIF           = AddressType{"base58", QTUMAlphabet, "doubleSHA256", "", 32, []byte{0x80}, nil}
	QTUM_mainnetPrivateWIFCompressed = AddressType{"base58", QTUMAlphabet, "doubleSHA256", "", 32, []byte{0x80}, []byte{0x01}}
	QTUM_mainnetPublicBIP32          = AddressType{"base58", QTUMAlphabet, "doubleSHA256", "", 74, []byte{0x04, 0x88, 0xB2, 0x1E}, nil}
	QTUM_mainnetPrivateBIP32         = AddressType{"base58", QTUMAlphabet, "doubleSHA256", "", 74, []byte{0x04, 0x88, 0xAD, 0xE4}, nil}
	QTUM_testnetAddressP2PKH         = AddressType{"base58", QTUMAlphabet, "doubleSHA256", "h160", 20, []byte{0x78}, nil}
	QTUM_testnetAddressP2SH          = AddressType{"base58", QTUMAlphabet, "doubleSHA256", "h160", 20, []byte{0x6E}, nil}
	QTUM_testnetPrivateWIF           = AddressType{"base58", QTUMAlphabet, "doubleSHA256", "", 32, []byte{0xEF}, nil}
	QTUM_testnetPrivateWIFCompressed = AddressType{"base58", QTUMAlphabet, "doubleSHA256", "", 32, []byte{0xEF}, []byte{0x01}}
	QTUM_testnetPublicBIP32          = AddressType{"base58", QTUMAlphabet, "doubleSHA256", "", 74, []byte{0x04, 0x35, 0x87, 0xCF}, nil}
	QTUM_testnetPrivateBIP32         = AddressType{"base58", QTUMAlphabet, "doubleSHA256", "", 74, []byte{0x04, 0x35, 0x83, 0x94}, nil}

	//DCRD stuff
	DCRD_mainnetAddressP2PKH      = AddressType{"base58", DCRDAlphabet, "doubleBlake256", "ripemd160", 20, []byte{0x07, 0x3f}, nil} //PubKeyHashAddrID, stars with Ds
	DCRD_mainnetAddressP2PK       = AddressType{"base58", DCRDAlphabet, "doubleBlake256", "ripemd160", 20, []byte{0x13, 0x86}, nil} //PubKeyAddrID,stars with Dk
	DCRD_mainnetAddressPKHEdwards = AddressType{"base58", DCRDAlphabet, "doubleBlake256", "ripemd160", 20, []byte{0x07, 0x1f}, nil} //PKHEdwardsAddrID,starts with De
	DCRD_mainnetAddressPKHSchnorr = AddressType{"base58", DCRDAlphabet, "doubleBlake256", "ripemd160", 20, []byte{0x07, 0x01}, nil} //PKHSchnorrAddrID,starts with DS
	DCRD_mainnetAddressP2SH       = AddressType{"base58", DCRDAlphabet, "doubleBlake256", "ripemd160", 20, []byte{0x07, 0x1a}, nil} //ScriptHashAddrID,starts with Dc
	DCRD_mainnetAddressPrivate    = AddressType{"base58", DCRDAlphabet, "doubleBlake256", "ripemd160", 20, []byte{0x22, 0xde}, nil} // PrivateKeyID, starts with Pm

	DCRD_testnetAddressP2PKH        = AddressType{"base58", DCRDAlphabet, "doubleBlake256", "ripemd160", 20, []byte{0x0f, 0x21}, nil} //PubKeyHashAddrID,starts with Ts
	DCRD_testnetAddressP2PK         = AddressType{"base58", DCRDAlphabet, "doubleBlake256", "ripemd160", 20, []byte{0x28, 0xf7}, nil} //PubKeyAddrID, starts with Tk
	DCRD_testnetAddressPKHEdwards   = AddressType{"base58", DCRDAlphabet, "doubleBlake256", "ripemd160", 20, []byte{0x0f, 0x01}, nil} //PKHEdwardsAddrID,starts with Te
	DCRD_testnetAddressP2PKHSchnorr = AddressType{"base58", DCRDAlphabet, "doubleBlake256", "ripemd160", 20, []byte{0x0e, 0xe3}, nil} //PKHSchnorrAddrID,starts with TS
	DCRD_testnetAddressP2SH         = AddressType{"base58", DCRDAlphabet, "doubleBlake256", "ripemd160", 20, []byte{0x0e, 0xfc}, nil} //ScriptHashAddrID,starts with Tc
	DCRD_testnetAddressPrivate      = AddressType{"base58", DCRDAlphabet, "doubleBlake256", "ripemd160", 20, []byte{0x23, 0x0e}, nil} //PrivateKeyID,starts with Pt

	DCRD_simnetAddressP2PKH      = AddressType{"base58", DCRDAlphabet, "doubleBlake256", "ripemd160", 20, []byte{0x0e, 0x91}, nil} //PubKeyHashAddrID,starts with Ss
	DCRD_simnetAddressP2PK       = AddressType{"base58", DCRDAlphabet, "doubleBlake256", "ripemd160", 20, []byte{0x27, 0x6f}, nil} //PubKeyAddrID,starts with Sk
	DCRD_simnetAddressPKHEdwards = AddressType{"base58", DCRDAlphabet, "doubleBlake256", "ripemd160", 20, []byte{0x0e, 0x71}, nil} //PKHEdwardsAddrID,starts with Se
	DCRD_simnetAddressPKHSchnorr = AddressType{"base58", DCRDAlphabet, "doubleBlake256", "ripemd160", 20, []byte{0x0e, 0x53}, nil} //PKHSchnorrAddrID,starts with SS
	DCRD_simnetAddressP2SH       = AddressType{"base58", DCRDAlphabet, "doubleBlake256", "ripemd160", 20, []byte{0x0e, 0x6c}, nil} //ScriptHashAddrID,starts with Sc
	DCRD_simnetAddressPrivate    = AddressType{"base58", DCRDAlphabet, "doubleBlake256", "ripemd160", 20, []byte{0x23, 0x07}, nil} //PrivateKeyID, starts with Ps

	//Nebulas stuff
	NAS_AccountAddress       = AddressType{"base58", NASAlphabet, "sha3_256", "sha3_256_ripemd160", 20, []byte{0x19, 0x57}, nil}
	NAS_SmartContractAddress = AddressType{"base58", NASAlphabet, "sha3_256", "sha3_256_ripemd160", 20, []byte{0x19, 0x58}, nil}

	//TRON stuff
	TRON_mainnetAddress = AddressType{"base58", TRONAlphabet, "doubleSHA256", "keccak256_last_twenty", 20, []byte{0x41}, nil}
	TRON_testnetAddress = AddressType{"base58", TRONAlphabet, "doubleSHA256", "keccak256_last_twenty", 20, []byte{0xa0}, nil}
	//ICX stuff
	ICX_walletAddress = AddressType{"ICX", "", "hx", "sha3_256_last_twenty", 20, nil, nil}

	//VSYS stuff
	VSYS_mainnetAddress = AddressType{"base58", VSYSAlphabet, "blake2b_and_keccak256_first_twenty", "blake2b_and_keccak256_first_twenty", 20, []byte{0x05, 0x4D}, nil}
	VSYS_testnetAddress = AddressType{"base58", VSYSAlphabet, "blake2b_and_keccak256_first_twenty", "blake2b_and_keccak256_first_twenty", 20, []byte{0x05, 0x54}, nil}

	//EOS stuff
	EOS_mainnetPublic               = AddressType{"eos", BTCAlphabet, "ripemd160", "", 33, []byte(EOSPublicKeyPrefixCompat), nil}
	EOS_mainnetPrivateWIF           = AddressType{"base58", BTCAlphabet, "doubleSHA256", "", 32, []byte{0x80}, nil}
	EOS_mainnetPrivateWIFCompressed = AddressType{"base58", BTCAlphabet, "doubleSHA256", "", 32, []byte{0x80}, []byte{0x01}}

	//AE stuff
	AE_mainnetAddress = AddressType{"aeternity", BTCAlphabet, "doubleSHA256", "", 32, []byte(AEPrefixAccountPubkey), nil}

	//ATOM stuff
	ATOM_mainnetAddress = AddressType{"bech32", ATOMBech32Alphabet, "cosmos", "h160", 20, nil, nil}
	ATOM_testnetAddress = AddressType{"bech32", ATOMBech32Alphabet, "cosmos", "h160", 20, nil, nil}

	//ELA stuff
	ELA_Address = AddressType{"base58", BTCAlphabet, "doubleSHA256", "h160", 20, []byte{0x21}, nil}

	//WICC stuff
	WICC_mainnetAddressP2PKH = AddressType{"base58", BTCAlphabet, "doubleSHA256", "h160", 20, []byte{0x49}, nil}
	WICC_testnetAddressP2PKH = AddressType{"base58", BTCAlphabet, "doubleSHA256", "h160", 20, []byte{0x87}, nil}

	//TV stuff
	TV_mainnetAddress = AddressType{"base58", VSYSAlphabet, "blake2b_and_keccak256_first_twenty", "blake2b_and_keccak256_first_twenty", 20, []byte{0x1D, 0x3B}, nil}
	TV_testnetAddress = AddressType{"base58", VSYSAlphabet, "blake2b_and_keccak256_first_twenty", "blake2b_and_keccak256_first_twenty", 20, []byte{0x1D, 0x54}, nil}

	//HC stuff
	HC_mainnetPublicAddress     = AddressType{"base58", HCAlphabet, "doubleBlake256", "h160", 20, []byte{0x09, 0x7F}, nil}
	HC_mainnetAddressP2PK       = AddressType{"base58", HCAlphabet, "doubleBlake256", "h160", 20, []byte{0x19, 0xa4}, nil} //PubKeyAddrID,stars with Hk
	HC_mainnetAddressP2PKBliss  = AddressType{"base58", HCAlphabet, "doubleBlake256", "h160", 20, []byte{0x07, 0xc3}, nil} //PubKeyAddrID,stars with Hk
	HC_mainnetAddressP2PKH      = AddressType{"base58", HCAlphabet, "doubleBlake256", "h160", 20, []byte{0x09, 0x7f}, nil} //PubKeyHashAddrID, stars with Hs
	HC_mainnetAddressPKHEdwards = AddressType{"base58", HCAlphabet, "doubleBlake256", "h160", 20, []byte{0x09, 0x60}, nil} //PKHEdwardsAddrID,starts with He
	HC_mainnetAddressPKHSchnorr = AddressType{"base58", HCAlphabet, "doubleBlake256", "h160", 20, []byte{0x09, 0x41}, nil} //PKHSchnorrAddrID,starts with HS
	HC_mainnetAddressPKHBliss   = AddressType{"base58", HCAlphabet, "doubleBlake256", "h160", 20, []byte{0x09, 0x58}, nil} //PKHSchnorrAddrID,starts with Hb
	HC_mainnetAddressP2SH       = AddressType{"base58", HCAlphabet, "doubleBlake256", "h160", 20, []byte{0x09, 0x5a}, nil} //ScriptHashAddrID,starts with Hc
	HC_mainnetAddressPrivate    = AddressType{"base58", HCAlphabet, "doubleBlake256", "h160", 20, []byte{0x19, 0xab}, nil} // PrivateKeyID, starts with Hm

	HC_testnetAddressP2PK         = AddressType{"base58", HCAlphabet, "doubleBlake256", "h160", 20, []byte{0x28, 0xf7}, nil} //PubKeyAddrID, starts with Tk
	HC_testnetAddressP2PKBliss    = AddressType{"base58", HCAlphabet, "doubleBlake256", "h160", 20, []byte{0x0c, 0x66}, nil} //PubKeyAddrID, starts with Tk
	HC_testnetAddressP2PKH        = AddressType{"base58", HCAlphabet, "doubleBlake256", "h160", 20, []byte{0x0f, 0x21}, nil} //PubKeyHashAddrID,starts with Ts
	HC_testnetAddressPKHEdwards   = AddressType{"base58", HCAlphabet, "doubleBlake256", "h160", 20, []byte{0x0f, 0x01}, nil} //PKHEdwardsAddrID,starts with Te
	HC_testnetAddressP2PKHSchnorr = AddressType{"base58", HCAlphabet, "doubleBlake256", "h160", 20, []byte{0x0e, 0xe3}, nil} //PKHSchnorrAddrID,starts with TS
	HC_testnetAddressPKHBliss     = AddressType{"base58", HCAlphabet, "doubleBlake256", "h160", 20, []byte{0x0e, 0xf9}, nil} //PKHSchnorrAddrID,starts with Tb
	HC_testnetAddressP2SH         = AddressType{"base58", HCAlphabet, "doubleBlake256", "h160", 20, []byte{0x0e, 0xfc}, nil} //ScriptHashAddrID,starts with Tc
	HC_testnetAddressPrivate      = AddressType{"base58", HCAlphabet, "doubleBlake256", "h160", 20, []byte{0x23, 0x0e}, nil} //PrivateKeyID,starts with Pt

	HC_simnetAddressP2PK       = AddressType{"base58", HCAlphabet, "doubleBlake256", "h160", 20, []byte{0x27, 0x6f}, nil} //PubKeyAddrID,starts with Sk
	HC_simnetAddressP2PKBliss  = AddressType{"base58", HCAlphabet, "doubleBlake256", "h160", 20, []byte{0x0b, 0xef}, nil} //PubKeyAddrID,starts with Sk
	HC_simnetAddressP2PKH      = AddressType{"base58", HCAlphabet, "doubleBlake256", "h160", 20, []byte{0x0e, 0x91}, nil} //PubKeyHashAddrID,starts with Ss
	HC_simnetAddressPKHEdwards = AddressType{"base58", HCAlphabet, "doubleBlake256", "h160", 20, []byte{0x0e, 0x71}, nil} //PKHEdwardsAddrID,starts with Se
	HC_simnetAddressPKHSchnorr = AddressType{"base58", HCAlphabet, "doubleBlake256", "h160", 20, []byte{0x0e, 0x53}, nil} //PKHSchnorrAddrID,starts with SS
	HC_simnetAddressPKHBliss   = AddressType{"base58", HCAlphabet, "doubleBlake256", "h160", 20, []byte{0x0e, 0x69}, nil} //PKHBlissAddrID,starts with Sb
	HC_simnetAddressP2SH       = AddressType{"base58", HCAlphabet, "doubleBlake256", "h160", 20, []byte{0x0e, 0x6c}, nil} //ScriptHashAddrID,starts with Sc
	HC_simnetAddressPrivate    = AddressType{"base58", HCAlphabet, "doubleBlake256", "h160", 20, []byte{0x23, 0x07}, nil} //PrivateKeyID, starts with Ps


	BNB_mainnetAddress = AddressType{"bech32", BTCBech32Alphabet, "bnb", "h160", 20, nil, nil}

	BSV_mainnetAddressP2PKH = AddressType{"base58", BTCAlphabet, "doubleSHA256", "h160", 20, []byte{0x00}, nil}
	BSV_mainnetAddressP2SH = AddressType{"base58", BTCAlphabet, "doubleSHA256", "h160", 20, []byte{0x05}, nil}

	EVA_mainnetAddress = AddressType{"bech32", ATOMBech32Alphabet, "eva", "h160", 20, nil, nil}
	EVA_testnetAddress = AddressType{"bech32", ATOMBech32Alphabet, "eva", "h160", 20, nil, nil}

	XCH_mainnetAddress = AddressType{"bech32m", XCHBech32Alphabet, "xch", "", 32, nil, nil}
)
