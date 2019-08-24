package addressEncoder

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/blocktree/go-owcrypt"
)

func Test_ttt(t *testing.T) {
	hash, _ := hex.DecodeString("7554d4fb989c873b8e84da7197b728086e9c6f56")
	fmt.Println(AddressEncode(hash, BTC_mainnetAddressP2PKH))

	hash, _ = hex.DecodeString("132f3a72f4d3559226bbaa45bcb7ede4d533bd7e")
	fmt.Println(AddressEncode(hash, BTC_mainnetAddressP2PKH))

	hash, _ = AddressDecode("1MZZuJRkn4zA3VmDZPopzWZ7M9G3LqsXW3", BTC_mainnetAddressP2PKH)
	fmt.Println(hex.EncodeToString(hash))

	hash, _ = AddressDecode("1BhPgfzoNqoUeWniegWhgbqPuf9vnCrVGH", BTC_mainnetAddressP2PKH)
	fmt.Println(hex.EncodeToString(hash))
}
func Test_btc_address(t *testing.T) {
	m_p2pkh_hash160 := []byte{0x62, 0x31, 0xf1, 0x00, 0x5e, 0x86, 0xc0, 0x3d, 0x5f, 0xbd, 0x41, 0x77, 0x69, 0x85, 0xd0, 0x94, 0xcc, 0xb6, 0x82, 0xd3}
	m_p2sh_hash160 := []byte{0x6c, 0x2a, 0xc3, 0xce, 0x63, 0x85, 0x1b, 0x90, 0x50, 0x4f, 0x75, 0xc5, 0xf3, 0x97, 0x87, 0x48, 0x22, 0xb5, 0x29, 0xc6}
	m_privateKey := []byte{0xf3, 0x8b, 0x35, 0x53, 0x51, 0x50, 0xef, 0x6e, 0x24, 0x46, 0xe4, 0xaa, 0x4d, 0x1e, 0x55, 0xaf, 0x31, 0xeb, 0xcc, 0x84, 0xef, 0x96, 0x04, 0xd4, 0x21, 0x12, 0xe5, 0xe8, 0x3e, 0xe9, 0xbc, 0x3a}

	fmt.Println("mainnet p2pkh address encode:")
	m_p2pkh_addr := AddressEncode(m_p2pkh_hash160, BTC_mainnetAddressP2PKH)

	if m_p2pkh_addr != "19xD3nnvEiu7Uqd8irRvF3j5ExLb4ZtSju" {
		t.Error("btc mainnet p2pkh address encode wrong result!")
	} else {
		fmt.Println("btcP2Pkh encoded result:", m_p2pkh_addr)
	}

	fmt.Println("mainnet p2pkh address decode")
	m_p2pkh_check, err := AddressDecode(m_p2pkh_addr, BTC_mainnetAddressP2PKH)
	if err != nil {
		t.Error("btc mainnet p2pkh address decode error!")
	} else {
		for i := 0; i < BTC_mainnetAddressP2PKH.HashLen; i++ {
			if m_p2pkh_check[i] != m_p2pkh_hash160[i] {
				t.Error("btc mainnet p2pkh address decode wrong result!")
				break
			}
		}
		fmt.Println("btcP2Pkh decode result:", hex.EncodeToString(m_p2pkh_check[:]))
	}

	fmt.Println("mainnet p2sh address encode:")
	m_p2sh_addr := AddressEncode(m_p2sh_hash160, BTC_mainnetAddressP2SH)

	if m_p2sh_addr != "3BYx8ciMdywxd2bbn5h9V7EAZtzLg2RhhX" {
		t.Error("btc mainnet p2sh address encode wrong result!")
	} else {
		fmt.Println("encoded result:", m_p2sh_addr)
	}

	fmt.Println("mainnet p2sh address decode")
	m_p2sh_check, err := AddressDecode(m_p2sh_addr, BTC_mainnetAddressP2SH)
	if err != nil {
		t.Error("btc mainnet p2sh address decode error!")
	} else {
		for i := 0; i < BTC_mainnetAddressP2SH.HashLen; i++ {
			if m_p2sh_check[i] != m_p2sh_hash160[i] {
				t.Error("btc mainnet p2sh address decode wrong result!")
				break
			}
		}
		fmt.Println("decode result:", hex.EncodeToString(m_p2sh_check[:]))
	}

	fmt.Println("mainnet prikey WIF-Compressed encode:")
	m_pri_wif_comp := AddressEncode(m_privateKey, BTC_mainnetPrivateWIFCompressed)

	if m_pri_wif_comp != "L5P8PR3euZKUFsHJ3jRSzaLSXbBUXje8hR9fcsKzQSp9zoxZAqCS" {
		t.Error("btc mainnet prikey WIF-Compressed encode wrong result!")
	} else {
		fmt.Println("encoded result:", m_pri_wif_comp)
	}

	fmt.Println("mainnet prikey WIF-Compressed decode:")
	m_pri_wif_comp_check, err := AddressDecode(m_pri_wif_comp, BTC_mainnetPrivateWIFCompressed)
	if err != nil {
		t.Error("btc mainnet prikey WIF-Compressed decode error!")
	} else {
		for i := 0; i < BTC_mainnetPrivateWIFCompressed.HashLen; i++ {
			if m_pri_wif_comp_check[i] != m_privateKey[i] {
				t.Error("btc mainnet prikey WIF-Compressed decode wrong result!")
				break
			}
		}
		fmt.Println("decode result:", hex.EncodeToString(m_pri_wif_comp_check[:]))
	}

}

func Test_ltc_address(t *testing.T) {
	/*
		m_p2pkh_hash160 := []byte{0x62, 0x31, 0xf1, 0x00, 0x5e, 0x86, 0xc0, 0x3d, 0x5f, 0xbd, 0x41, 0x77, 0x69, 0x85, 0xd0, 0x94, 0xcc, 0xb6, 0x82, 0xd3}
		address := AddressEncode(m_p2pkh_hash160, LTC_mainnetAddressP2PKH)
		fmt.Println(address)
		chk, err := AddressDecode(address, LTC_mainnetAddressP2PKH)
		if err != nil {
			t.Error("decode error")
		} else {
			fmt.Println(hex.EncodeToString(chk))
		}
	*/
	addr := "QVk4MvUu7Wb7tZ1wvAeiUvdF7wxhvpyLLK"
	chk, err := AddressDecode(addr, LTC_testnetAddressP2SH2)
	if err != nil {
		t.Error("decode error")
	} else {
		fmt.Println("LTC decode result:", hex.EncodeToString(chk))
	}
	address := AddressEncode(chk, LTC_testnetAddressP2SH2)
	fmt.Println("LTC encode result:", address)

}
func Test_btc_address_fromkey(t *testing.T) {
	pubkey := []byte{0x04, 0x7D, 0xB2, 0x27, 0xD7, 0x09, 0x4C, 0xE2, 0x15, 0xC3, 0xA0, 0xF5, 0x7E, 0x1B, 0xCC, 0x73, 0x25, 0x51, 0xFE, 0x35, 0x1F, 0x94, 0x24, 0x94, 0x71, 0x93, 0x45, 0x67, 0xE0, 0xF5, 0xDC, 0x1B, 0xF7, 0x95, 0x96, 0x2B, 0x8C, 0xCC, 0xB8, 0x7A, 0x2E, 0xB5, 0x6B, 0x29, 0xFB, 0xE3, 0x7D, 0x61, 0x4E, 0x2F, 0x4C, 0x3C, 0x45, 0xB7, 0x89, 0xAE, 0x4F, 0x1F, 0x51, 0xF4, 0xCB, 0x21, 0x97, 0x2F, 0xFD}
	hash := []byte{0x1e, 0x35, 0x3b, 0x2e, 0x11, 0x25, 0xa1, 0x4e, 0xdd, 0xc2, 0x2d, 0xce, 0x7d, 0x46, 0xd7, 0xc4, 0xb5, 0xea, 0xc9, 0x91}
	ret := AddressEncode(pubkey, BTC_mainnetAddressP2PKH)
	fmt.Println(ret)

	chk, err := AddressDecode(ret, BTC_mainnetAddressP2PKH)
	if err != nil {
		t.Error("decode error")
	} else {
		for i := 0; i < 20; i++ {
			if chk[i] != hash[i] {
				t.Error("decode wrong result")
			}
		}
		fmt.Println(hex.EncodeToString(chk))
	}
}
func Test_btc_bech32_address(t *testing.T) {

	address := "bc1qvgclzqz7smqr6haag9mknpwsjnxtdqkncr64kd"
	ret, err := AddressDecode(address, BTC_mainnetAddressBech32V0)
	if err != nil {
		t.Error("decode error")
	} else {
		fmt.Println(hex.EncodeToString(ret))
	}

	addresschk := AddressEncode(ret, BTC_mainnetAddressBech32V0)
	if addresschk != address {
		t.Error("encode error")
	} else {
		fmt.Println(addresschk)
	}
}

func Test_btc_bech32_testnet_address(t *testing.T) {
	//2N3Tkn6AAw1sLp2AEov68y9bPq3yC1bTj5t,tb1qq3cseq3st0rtt480n7xg9ver2a0v84yudp207x

	address := "tb1qq3cseq3st0rtt480n7xg9ver2a0v84yudp207x" //001404710c82305bc6b5d4ef9f8c82b323575ec3d49c
	ret, err := AddressDecode(address, BTC_testnetAddressBech32V0)
	if err != nil {
		t.Error("decode error")
	} else {
		fmt.Println(hex.EncodeToString(ret))
	}

	addresschk := AddressEncode(ret, BTC_testnetAddressBech32V0)
	if addresschk != address {
		t.Error("encode error")
	} else {
		fmt.Println(addresschk)
	}

	addrp2sh := "2N3Tkn6AAw1sLp2AEov68y9bPq3yC1bTj5t"
	ret2, err := AddressDecode(addrp2sh, BTC_testnetAddressP2SH)
	if err != nil {
		t.Error("decode error")
	} else {
		fmt.Println(hex.EncodeToString(ret2))
	}
}

func Test_bch_address(t *testing.T) {
	cashAddress := "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"
	cashHash := []byte{0, 0x76, 0xa0, 0x40, 0x53, 0xbd, 0xa0, 0xa8, 0x8b, 0xda, 0x51, 0x77, 0xb8, 0x6a, 0x15, 0xc3, 0xb2, 0x9f, 0x55, 0x98, 0x73}

	fmt.Println("BCH CashAddress Encode test")

	cashAddressChk := AddressEncode(cashHash, BCH_mainnetAddressCash)

	if cashAddressChk != cashAddress {
		t.Error("BCH cashaddress encode result wrong")
	} else {
		fmt.Println("encode result:", cashAddressChk)
	}

	fmt.Println("BCH CashAddress Decode test")
	cashHashChk, err := AddressDecode(cashAddress, BCH_mainnetAddressCash)
	if err != nil {
		t.Error("BCH cashaddress decode error")
	} else {
		for i := 0; i < len(cashHashChk); i++ {
			if cashHashChk[i] != cashHash[i] {
				t.Error("BCH cashaddress decode result wrong")
				break
			}
		}
		fmt.Println("decode result:", hex.EncodeToString(cashHashChk[:]))
	}

}

func Test_eth_address(t *testing.T) {
	/*
		keccak256_hash := []byte{0xdb, 0xf0, 0x3b, 0x40, 0x7c, 0x01, 0xe7, 0xcd, 0x3c, 0xbe, 0xa9, 0x95, 0x09, 0xd9, 0x3f, 0x8d, 0xdd, 0xc8, 0xc6, 0xfb}
		//decode_addr:=make([]byte,20)
		//var encode_addr string
		//str=eip55.Eip55_encode(addr[:])
		fmt.Println("ETH CashAddress Encode test")
		eth_encode_addr := AddressEncode(keccak256_hash, ETH_mainnetPublicAddress)

		if eth_encode_addr != "dbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB" {
			t.Error("ETH cashaddress encode wrong result")
		} else {
			fmt.Println("ETH encode result:", string(eth_encode_addr))
		}

		fmt.Println("ETH Cashaddress Decode test")
		eth_decode_addr, err := AddressDecode(eth_encode_addr, ETH_mainnetPublicAddress)
		if err != nil {
			t.Error("ETH cashaddress decode error")
		} else {
			fmt.Printf("ETH decode result:")
			for _, t := range eth_decode_addr {
				fmt.Printf("0x%x ", t)
			}
			fmt.Printf("\n")
		}
	*/
	//pubkey := []byte{0x93, 0x69, 0xAD, 0x41, 0xDF, 0xF3, 0xE5, 0xC7, 0x08, 0x64, 0xC3, 0x96, 0x38, 0x9C, 0xE4, 0x6E, 0x1C, 0x0F, 0xCD, 0xA0, 0xAE, 0x0A, 0x95, 0x28, 0xD1, 0xB8, 0x9C, 0x4B, 0x46, 0x6F, 0x12, 0xFD, 0x67, 0x00, 0xE5, 0x8A, 0xF1, 0x2E, 0x44, 0x97, 0x5D, 0xAD, 0xAC, 0xA2, 0xB8, 0x9D, 0xD3, 0x58, 0x36, 0x67, 0xD7, 0xA2, 0x12, 0x3E, 0x3C, 0xC3, 0x3C, 0x5D, 0xF6, 0x3D, 0xF4, 0x34, 0x59, 0x07}
	//EncodeAddr := AddressEncode(pubkey, ETH_mainnetPublicAddress)
	//fmt.Println("ETH address encode result::", EncodeAddr)
	EncodeAddr := "0x50068fd632c1a6e6c5bd407b4ccf8861a589e776"
	DecodeAddr, err := AddressDecode(EncodeAddr, ETH_mainnetPublicAddress)
	if err != nil {
		t.Error("ETH cashaddress decode error")
	} else {
		fmt.Printf("ETH decode result:")
		for _, t := range DecodeAddr {
			fmt.Printf("0x%x ", t)
		}
	}

}

func Test_DCRD_address(t *testing.T) {
	//PubKeyHashAddrID test......
	mainnet_P2PKH_encodeAddress := "DsUZxxoHJSty8DCfwfartwTYbuhmVct7tJu"
	mainnet_P2PKH_decodeAddress := []byte{0x27, 0x89, 0xd5, 0x8c, 0xfa, 0x09, 0x57, 0xd2, 0x06, 0xf0, 0x25, 0xc2, 0xaf, 0x05, 0x6f, 0xc8, 0xa7, 0x7c, 0xeb, 0xb0}
	fmt.Println("DCRD mainnet P2PKH  address decode test")
	mainnet_P2PKH_decodeAddressChk, err := AddressDecode(mainnet_P2PKH_encodeAddress, DCRD_mainnetAddressP2PKH)
	if err != nil {
		t.Error("DCRD mainnet P2PKH address decode error")
	} else {
		fmt.Printf("DCRD   mainnet P2PKH address decode result:")
		for _, s := range mainnet_P2PKH_decodeAddressChk {
			fmt.Printf("0x%x ", s)
		}
		fmt.Printf("\n")
	}

	fmt.Println("DCRD mainnet P2PKH  address encode test")
	mainnet_P2PKH_encodeAddressChk := AddressEncode(mainnet_P2PKH_decodeAddress, DCRD_mainnetAddressP2PKH)
	if mainnet_P2PKH_encodeAddressChk != mainnet_P2PKH_encodeAddress {
		t.Error("DCRD mainnet P2PKH address encode error")
	} else {
		fmt.Println("DCRD mainnet P2PKH address encode result:", string(mainnet_P2PKH_encodeAddressChk))
	}

	//PubKeyHashAddrID test......
	testnet_P2PKH_encodeAddress := "Tso2MVTUeVrjHTBFedFhiyM7yVTbieqp91h"
	testnet_P2PKH_decodeAddress := []byte{0xf1, 0x5d, 0xa1, 0xcb, 0x8d, 0x1b, 0xcb, 0x16, 0x2c, 0x6a, 0xb4, 0x46, 0xc9, 0x57, 0x57, 0xa6, 0xe7, 0x91, 0xc9, 0x16}
	fmt.Println("DCRD testnet P2PKH  address decode test")
	testnet_P2PKH_decodeAddressChk, err := AddressDecode(testnet_P2PKH_encodeAddress, DCRD_testnetAddressP2PKH)
	if err != nil {
		t.Error("DCRD testnet P2PKH address decode error")
	} else {
		fmt.Printf("DCRD   testnet P2PKH address decode result:")
		for _, s := range testnet_P2PKH_decodeAddressChk {
			fmt.Printf("0x%x ", s)
		}
		fmt.Printf("\n")
	}
	fmt.Println("DCRD testnet P2PKH  address encode test")
	testnet_P2PKH_encodeAddressChk := AddressEncode(testnet_P2PKH_decodeAddress, DCRD_testnetAddressP2PKH)
	if testnet_P2PKH_encodeAddressChk != testnet_P2PKH_encodeAddress {
		t.Error("DCRD testnet P2PKH address encode error")
	} else {
		fmt.Println("DCRD mainnet P2PKH address encode result:", string(testnet_P2PKH_encodeAddressChk))
	}
}

func Test_NAS_address(t *testing.T) {

	//NAS Account address test......
	Account_encodeAddress := "n1TV3sU6jyzR4rJ1D7jCAmtVGSntJagXZHC"
	Account_decodeAddressChk, err := AddressDecode(Account_encodeAddress, NAS_AccountAddress)
	if err != nil {
		t.Error("NAS account address decode error")
	} else {
		fmt.Println("NAS account address decode result:", hex.EncodeToString(Account_decodeAddressChk))
	}
	Account_encodeAddressChk := AddressEncode(Account_decodeAddressChk, NAS_AccountAddress)
	if Account_encodeAddressChk != "n1TV3sU6jyzR4rJ1D7jCAmtVGSntJagXZHC" {
		t.Error("NAS Account address encode error")
	} else {
		fmt.Println("NAS address encode result:", string(Account_encodeAddressChk))
	}

	//NAS smart contract address test......
	SmartContract_encodeAddress := "n1sLnoc7j57YfzAVP8tJ3yK5a2i56QrTDdK"
	SmartContract_decodeAddressChk, err := AddressDecode(SmartContract_encodeAddress, NAS_SmartContractAddress)
	if err != nil {
		t.Error("NAS smart contract address decode error")
	} else {
		fmt.Println("NAS smart contract address decode result:", hex.EncodeToString(SmartContract_decodeAddressChk))
	}
	SmartContract_encodeAddressChk := AddressEncode(SmartContract_decodeAddressChk, NAS_SmartContractAddress)
	if SmartContract_encodeAddressChk != "n1sLnoc7j57YfzAVP8tJ3yK5a2i56QrTDdK" {
		t.Error("NAS smart contract encode error")
	} else {
		fmt.Println("NAS smart contract encode result:", string(SmartContract_encodeAddressChk))
	}
}

func Test_tmp(t *testing.T) {
	address1 := "QQfTuAKdRrTawjiPZRcQ6iaK9BgxwMDgXN"

	bytes, _ := AddressDecode(address1, QTUM_mainnetAddressP2PKH)
	fmt.Println(hex.EncodeToString(bytes))

	// in1 address QiZtY5ssbVis9MntBdqmcYuJWsP5BCGBX3
	//以下是地址的私钥
	address := "KxRGsMrnSRhcjmKDeajpWQXQi6agP8WiJ19djdGQ8gdWmzAsTFBe"
	ret, _ := AddressDecode(address, QTUM_mainnetPrivateWIFCompressed)
	fmt.Println(hex.EncodeToString(ret))

	//私钥解码后获得公钥
	pub, _ := owcrypt.GenPubkey(ret, owcrypt.ECC_CURVE_SECP256K1)

	//公钥获得公钥哈希
	pub = owcrypt.PointCompress(pub, owcrypt.ECC_CURVE_SECP256K1)

	pkh := owcrypt.Hash(pub, 0, owcrypt.HASH_ALG_HASH160)

	fmt.Println(hex.EncodeToString(pkh))

	//公钥哈希通过Base58编码获得地址
	chk := AddressEncode(pkh, QTUM_mainnetAddressP2PKH)

	fmt.Println(chk)

	pkh = append([]byte{0, 20}, pkh...)

	fmt.Println(hex.EncodeToString(pkh))

	pkh = owcrypt.Hash(pkh, 0, owcrypt.HASH_ALG_HASH160)

	fmt.Println(hex.EncodeToString(pkh))
}

func Test_base64(t *testing.T) {
	const encodeStd = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	s := new(Encoding)
	var err error
	//msg := "Man is distinguished, not only by his reason, but by this singular passion from other animals, which is a lust of the mind, that by a perseverance of delight in the continued and indefatigable generation of knowledge, exceeds the short vehemence of any carnal pleasure."
	msg := []byte{0x83, 0xc1, 0xa3, 0x12, 0xf4, 0xdb, 0x5b, 0x9a, 0x15, 0x49, 0x5e, 0xda, 0xbc, 0xbe, 0x3b, 0xdf, 0x9e, 0xf8, 0xdf, 0xca, 0xde, 0xca, 0x1a, 0xde, 0xca, 0xea, 0xf2, 0x7a, 0xda, 0xde, 0x74, 0xb0, 0xd5, 0x2a, 0xcd, 0xa6, 0xd1, 0x03, 0x7b, 0xbf, 0x14, 0x6c, 0xda, 0x29, 0xb9, 0x30, 0x36, 0x8d, 0x09, 0x61, 0xa6, 0x70, 0x3d, 0xab, 0xbd, 0xc6, 0x71}
	s.padChar = StdPadding
	s.encode = []byte(encodeStd)
	encode := s.Base64Encode([]byte(msg))
	fmt.Println("base64 encode:=", encode)

	str := "g8GjEvTbW5oVSV7avL47357438reyhreyuryetredLDVKs2m0QN7vxRs2im5MDaNCWGmcD2rvcZx"
	//str:="Y0dXJwf3It4cnsrMZjEa/YXAFf1YzmuKL95JnRcVjtR+PE1VebQXoE8NifRxnLFzk5GMIoZQ51Fbq+o6ZTSb2AA="
	decode, err := s.Base64Decode(str)
	if err != nil {
		t.Error("base64 decode error!!!!")
	} else {
		fmt.Println("base64 decode=:", hex.EncodeToString(decode))
	}
}

func Test_TRON_address(t *testing.T) {
	pubkey := []byte{0x51, 0xe9, 0xaa, 0xaa, 0x16, 0x43, 0xf4, 0xf1, 0x35, 0x70, 0xcb, 0x16, 0x32, 0x4b, 0xa9, 0x34, 0x56, 0x70, 0xaa, 0xc6, 0x03, 0xb7, 0x51, 0x0f, 0x93, 0x34, 0xc1, 0xdc, 0xd0, 0x12, 0x3b, 0x0a, 0x26, 0x5b, 0x2c, 0x2b, 0x0e, 0xc5, 0x22, 0x7a, 0x89, 0xf8, 0x65, 0xc1, 0x55, 0xfc, 0x2f, 0xe3, 0x42, 0x2f, 0x2a, 0x47, 0x4b, 0xa0, 0x91, 0xef, 0x41, 0x06, 0xf1, 0x13, 0xb6, 0x87, 0xf0, 0x53}
	encodeAddr := AddressEncode(pubkey, TRON_mainnetAddress)
	fmt.Println("tron encodeAddr=:", string(encodeAddr))
	//encodeAddr = "TAJTMJuzvAqB8wmdUjRBVJW8CozfgrhpX3"
	decodeAddr, err := AddressDecode(encodeAddr, TRON_mainnetAddress)
	if err != nil {
		t.Error("tron addr decode error!!!!")
	} else {
		fmt.Println("tron decodeAddr=:", hex.EncodeToString(decodeAddr))
	}

	encodeTestnetAddr := AddressEncode(decodeAddr, TRON_testnetAddress)
	fmt.Println("tron encodeTestnetAddr=:", string(encodeTestnetAddr))
}

func Test_bch32_multi(t *testing.T) {
	addr := "tb1qk87tnszyj4528l6pa86zfqcl0d90c7vvkrt7j7rxlkxy9drvxqhsmwpg6q"

	hash, err := AddressDecode(addr, BTC_testnetAddressBech32V0)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Println(hex.EncodeToString(hash))
	}

	addrchk := AddressEncode(hash, BTC_testnetAddressBech32V0)
	if addrchk != addr {
		t.Error("encode failed !")
	} else {
		fmt.Println(addrchk)
	}

}
func Test_AddressCheck(t *testing.T) {
	var ret bool
	var err error
	//check main-net btc p2pkh address
	mainnet_btc_p2pkh_addr := "19xD3nnvEiu7Uqd8irRvF3j5ExLb4ZtSju"
	ret, err = AddressCheck(mainnet_btc_p2pkh_addr, "BTC")
	if ret == true && err == nil {
		fmt.Println("main net btc p2pkh address test success!!!")
	} else {
		fmt.Println("main net btc p2pkh address  test fail!!!")
	}
	//check main-net btc p2sh address
	mainnet_btc_p2sh_addr := "3BYx8ciMdywxd2bbn5h9V7EAZtzLg2RhhX"
	ret, err = AddressCheck(mainnet_btc_p2sh_addr, "BTC")
	if ret == true && err == nil {
		fmt.Println("main net btc p2sh address test success!!!")
	} else {
		fmt.Println("main net btc p2sh address  test fail!!!")
	}
	//check main-net btc bench32 address
	mainnet_btc_bench32_addr := "bc1qqypqxpq9mhu2k6vr97gsq4lfntyv7w7x34knte"
	ret, err = AddressCheck(mainnet_btc_bench32_addr, "BTC")
	if ret == true && err == nil {
		fmt.Println("main net btc bench32 address test success!!!")
	} else {
		fmt.Println("main net btc bench32 address  test fail!!!")
	}
	//check test-net btc p2pkh address
	//testnet_btc_p2pkh:="mvxN7bmFgnJ7khmZBLz7KwE6xcr3UN1CtT"
	testnet_btc_p2pkh := "n4o6E6cZXxcD3YYQu4EkoWUvTeX3nVvimz"
	ret, err = AddressCheck(testnet_btc_p2pkh, "BTC")
	if ret == true && err == nil {
		fmt.Println("test net btc p2pkh address test success!!!")
	} else {
		fmt.Println("test net btc p2pkh address  test fail!!!")
	}
	//check test-net btc p2sh
	testnet_btc_p2sh := "2NGXMvKx3tHzgZPPmyiYr2AcnxXREDYC9vk"
	ret, err = AddressCheck(testnet_btc_p2sh, "BTC")
	if ret == true && err == nil {
		fmt.Println("test net btc p2sh address test success!!!")
	} else {
		fmt.Println("test net btc p2sh address  test fail!!!")
	}
	//check main-net zec p2pkh address
	mainnet_zec_p2pkh := "t1HxthBM2DkriXFepEtrWo4xdFdHYNVmUG8"
	ret, err = AddressCheck(mainnet_zec_p2pkh, "ZEC")
	if ret == true && err == nil {
		fmt.Println("main net zec p2pkh address test success!!!")
	} else {
		fmt.Println("main net zec p2pkh address  test fail!!!")
	}
	//check main-net zec p2sh
	mainnet_zec_p2sh := "t3Jex1xQ8ANcjJmDBKjwXM4rFjnqhdA5xF4"
	ret, err = AddressCheck(mainnet_zec_p2sh, "ZEC")
	if ret == true && err == nil {
		fmt.Println("main net zec p2sh address test success!!!")
	} else {
		fmt.Println("main net zec p2sh address  test fail!!!")
	}
	//check test-net zec p2pkh address
	testnet_zec_p2pkh := "tmZ3w76PSkvNMZpueRsm2saujnk2qHprCLg"
	ret, err = AddressCheck(testnet_zec_p2pkh, "ZEC")
	if ret == true && err == nil {
		fmt.Println("test net zec p2pkh address test success!!!")
	} else {
		fmt.Println("test net zec p2pkh address  test fail!!!")
	}
	//check test-net zec p2sh address
	testnet_zec_p2sh := "t26e94dWG2qE6rTnvFUwZth2trH4sR7jiZR"
	ret, err = AddressCheck(testnet_zec_p2sh, "ZEC")
	if ret == true && err == nil {
		fmt.Println("test net zec p2sh address test success!!!")
	} else {
		fmt.Println("test net zec p2sh address  test fail!!!")
	}
	//check main-net ltc p2pkh address
	mainnet_ltc_p2pkh := "LiZY38njUbKK5kMTzrdUA8Cq9K8D9HBwKm"
	ret, err = AddressCheck(mainnet_ltc_p2pkh, "LTC")
	if ret == true && err == nil {
		fmt.Println("main net ltc p2pkh address test success!!!")
	} else {
		fmt.Println("main net ltc p2pkh address test fail!!!")
	}
	//check main-net ltc p2sh address
	mainnet_ltc_p2sh := "31nM1cyzC3q8i8AHPK8QDFkLV8ecnuuUCG"
	ret, err = AddressCheck(mainnet_ltc_p2sh, "LTC")
	if ret == true && err == nil {
		fmt.Println("main net ltc p2sh address test success!!!")
	} else {
		fmt.Println("main net ltc p2sh address test fail!!!")
	}
	//check main-net ltc p2sh2 address
	mainnet_ltc_p2sh2 := "M85iNdLf28FaxGg39zPQaqyHeQ9DuT1HQU"
	ret, err = AddressCheck(mainnet_ltc_p2sh2, "LTC")
	if ret == true && err == nil {
		fmt.Println("main net ltc p2sh2 address test success!!!")
	} else {
		fmt.Println("main net ltc p2sh2 address test fail!!!")
	}
	//check main-net ltc bench32 address
	mainnet_ltc_bench32 := "ltc1qqqqqpuwrmhu2k6vr97gsq4lfntyv7w7xxy2nal"
	ret, err = AddressCheck(mainnet_ltc_bench32, "LTC")
	if ret == true && err == nil {
		fmt.Println("main net ltc bench32 address test success!!!")
	} else {
		fmt.Println("main net ltc bench32 address test fail!!!")
	}
	//check test-net ltc p2pkh address
	testnet_ltc_p2pkh := "ltc1qqqqqpuwrmhu2k6vr97gsq4lfntyv7w7xxy2nal"
	ret, err = AddressCheck(testnet_ltc_p2pkh, "LTC")
	if ret == true && err == nil {
		fmt.Println("test net ltc p2pkh address test success!!!")
	} else {
		fmt.Println("test net ltc p2pkh address test fail!!!")
	}
	//check test-net ltc bench32 address
	testnet_ltc_bench32 := "2NGapyNqzGyLASatzXWd7emvMzRbJ4rxywj"
	ret, err = AddressCheck(testnet_ltc_bench32, "LTC")
	if ret == true && err == nil {
		fmt.Println("test net ltc bench32 address test success!!!")
	} else {
		fmt.Println("test net ltc bench32 address test fail!!!")
	}
	//check main-net bch  legacy address
	testnet_bch_legacy := "1QLbz6RX7cWS9da1jHLecCaAdZ6QjNfcjP"
	ret, err = AddressCheck(testnet_bch_legacy, "BCH")
	if ret == true && err == nil {
		fmt.Println("main net bch legacy address test success!!!")
	} else {
		fmt.Println("main net ltc legacy address test fail!!!")
	}
	//check main-net bch  cash address
	testnet_bch_cash := "bitcoincash:qqqs9ll3c0wl32mfsvhezqzhaxdv3nemcc988w0rxn"
	ret, err = AddressCheck(testnet_bch_cash, "BCH")
	if ret == true && err == nil {
		fmt.Println("main net bch cash address test success!!!")
	} else {
		fmt.Println("main net bch cash address test fail!!!")
	}
	//check main-net xtz  tz1 address
	mainnet_xtz_tz1 := "tz1iycVGryQop8nryZWcXfvtiK5KvxC5coUS"
	ret, err = AddressCheck(mainnet_xtz_tz1, "XTZ")
	if ret == true && err == nil {
		fmt.Println("main net xtz tz1 address test success!!!")
	} else {
		fmt.Println("main net xtz tz1 address test fail!!!")
	}
	//check main-net xtz  tz2 address
	mainnet_xtz_tz2 := "tz2XepTVTYqAjtRjFjZTCJu9FtLLSqhWewru"
	ret, err = AddressCheck(mainnet_xtz_tz2, "XTZ")
	if ret == true && err == nil {
		fmt.Println("main net xtz tz2 address test success!!!")
	} else {
		fmt.Println("main net xtz tz2 address test fail!!!")
	}
	//check main-net xtz  tz3 address
	mainnet_xtz_tz3 := "tz2XepTVTYqAjtRjFjZTCJu9FtLLSqhWewru"
	ret, err = AddressCheck(mainnet_xtz_tz3, "XTZ")
	if ret == true && err == nil {
		fmt.Println("main net xtz tz3 address test success!!!")
	} else {
		fmt.Println("main net xtz tz3 address test fail!!!")
	}
	//check main-net hc  p2pkh address
	mainnet_hc_p2pkh := "HsDCFUx2LzWBuaDjqpZZ9GZcZ9eQEoyuke9"
	ret, err = AddressCheck(mainnet_hc_p2pkh, "HC")
	if ret == true && err == nil {
		fmt.Println("main net hc p2pkh address test success!!!")
	} else {
		fmt.Println("main net hc p2pkh address test fail!!!")
	}
	//check main-net eth  p2pkh address
	mainnet_eth_p2pkh := "63ec3c7fe5682098a64a27e8a1abd973158bc255"
	ret, err = AddressCheck(mainnet_eth_p2pkh, "ETH")
	if ret == true && err == nil {
		fmt.Println("main net eth p2pkh address test success!!!")
	} else {
		fmt.Println("main net eth p2pkh address test fail!!!")
	}
	//check main-net qtum  p2pkh address
	mainnet_qtum_p2pkh := "QjwHHRHUzaPebgmDkrtx3CxkchtDW5eB9w"
	ret, err = AddressCheck(mainnet_qtum_p2pkh, "QTUM")
	if ret == true && err == nil {
		fmt.Println("main net qtum p2pkh address test success!!!")
	} else {
		fmt.Println("main net qtum p2pkh address test fail!!!")
	}
	//check main-net qtum  p2sh address
	mainnet_qtum_p2sh := "M7zoS2sNa9jg5eYiMvaJeAR3pNJe8gCT1L"
	ret, err = AddressCheck(mainnet_qtum_p2sh, "QTUM")
	if ret == true && err == nil {
		fmt.Println("main net qtum p2sh address test success!!!")
	} else {
		fmt.Println("main net qtum p2sh address test fail!!!")
	}
	//check test-net qtum  p2pkh address
	testnet_qtum_p2pkh := "qgtvhvhA6X6oRRprS7fBE9i3YpgQRYbkHr"
	ret, err = AddressCheck(testnet_qtum_p2pkh, "QTUM")
	if ret == true && err == nil {
		fmt.Println("test net qtum p2pkh address test success!!!")
	} else {
		fmt.Println("test net qtum p2pkh address test fail!!!")
	}
	//check test-net qtum  p2sh address
	testnet_qtum_p2sh := "mfWtrqiGziU3F6RzBvKzNtzBFn6yNbgMy2"
	ret, err = AddressCheck(testnet_qtum_p2sh, "QTUM")
	if ret == true && err == nil {
		fmt.Println("test net qtum p2sh address test success!!!")
	} else {
		fmt.Println("test net qtum p2sh address test fail!!!")
	}
	//check main-net dcrd  p2pkh address
	mainnet_dcrd_p2pkh := "DspJUEokqP5jXM1vqpwu1A7wNMw6Kr4wT3m"
	ret, err = AddressCheck(mainnet_dcrd_p2pkh, "DCRD")
	if ret == true && err == nil {
		fmt.Println("main net dcrd p2pkh address test success!!!")
	} else {
		fmt.Println("main net dcrd p2pkh address test fail!!!")
	}
	//check main-net dcrd  p2pk address
	mainnet_dcrd_p2pk := "bgVbKAGTjGTweyUXBLieYB1zXfQHWsbuA6D"
	ret, err = AddressCheck(mainnet_dcrd_p2pk, "DCRD")
	if ret == true && err == nil {
		fmt.Println("main net dcrd p2pk address test success!!!")
	} else {
		fmt.Println("main net dcrd p2pk address test fail!!!")
	}
	//check main-net dcrd  pkhedwards address
	mainnet_dcrd_pkhedwards := "DewVCxW5zzghpQJr8dh7eYvoiMoGZfaUJy1"
	ret, err = AddressCheck(mainnet_dcrd_pkhedwards, "DCRD")
	if ret == true && err == nil {
		fmt.Println("main net dcrd pkhedwards address test success!!!")
	} else {
		fmt.Println("main net dcrd pkhedwards address test fail!!!")
	}
	//check main-net dcrd  schnorr address
	mainnet_dcrd_schnorr := "DSU6oCkovJ2pF6NGky3DWHXdX2AQs8gk1B9"
	ret, err = AddressCheck(mainnet_dcrd_schnorr, "DCRD")
	if ret == true && err == nil {
		fmt.Println("main net dcrd schnorr address test success!!!")
	} else {
		fmt.Println("main net dcrd schnorr address test fail!!!")
	}
	//check main-net dcrd  p2sh address
	mainnet_dcrd_p2sh := "DcXYspUG83YQ9YCkvaXYUQfSBkmrSrL6kc4"
	ret, err = AddressCheck(mainnet_dcrd_p2sh, "DCRD")
	if ret == true && err == nil {
		fmt.Println("main net dcrd p2sh address test success!!!")
	} else {
		fmt.Println("main net dcrd p2sh address test fail!!!")
	}
	//check main-net dcrd  private address
	mainnet_dcrd_private := "24vdxJaJwxmr7xb5ngYb5qDt89SMBNETRv4d"
	ret, err = AddressCheck(mainnet_dcrd_private, "DCRD")
	if ret == true && err == nil {
		fmt.Println("main net dcrd private address test success!!!")
	} else {
		fmt.Println("main net dcrd private address test fail!!!")
	}
	//check test-net dcrd  p2pkh address
	testnet_dcrd_p2pkh := "24vdxJaJwxmr7xb5ngYb5qDt89SMBNETRv4d"
	ret, err = AddressCheck(testnet_dcrd_p2pkh, "DCRD")
	if ret == true && err == nil {
		fmt.Println("test net dcrd p2pkh address test success!!!")
	} else {
		fmt.Println("test net dcrd p2pkh address test fail!!!")
	}
	//check test-net dcrd  p2pk address
	testnet_dcrd_p2pk := "2Fm9oAbpfK58nNy3czkcb3Jp2RYP5wGu1T8k"
	ret, err = AddressCheck(testnet_dcrd_p2pk, "DCRD")
	if ret == true && err == nil {
		fmt.Println("test net dcrd p2pk address test success!!!")
	} else {
		fmt.Println("test net dcrd p2pk address test fail!!!")
	}
	//check test-net dcrd  pkhedwards address
	testnet_dcrd_pkhedwards := "TeYJA3VU8ydFNWqS9EFYYcWgRys1K71uK2R"
	ret, err = AddressCheck(testnet_dcrd_pkhedwards, "DCRD")
	if ret == true && err == nil {
		fmt.Println("test net dcrd pkhedwards address test success!!!")
	} else {
		fmt.Println("test net dcrd pkhedwards address test fail!!!")
	}
	//check test-net dcrd  schnorr address
	testnet_dcrd_schnorr := "TSsQJ2E4CGxuzERzdjUoWCramzL3gnH4bBQ"
	ret, err = AddressCheck(testnet_dcrd_schnorr, "DCRD")
	if ret == true && err == nil {
		fmt.Println("test net dcrd schnorr address test success!!!")
	} else {
		fmt.Println("test net dcrd schnorr address test fail!!!")
	}
	//check test-net dcrd  p2sh address
	testnet_dcrd_p2sh := "TcvrNdwWQ2UVtgGUoLy8UKzPSiwVGauxYJF"
	ret, err = AddressCheck(testnet_dcrd_p2sh, "DCRD")
	if ret == true && err == nil {
		fmt.Println("test net dcrd p2sh address test success!!!")
	} else {
		fmt.Println("test net dcrd p2sh address test fail!!!")
	}
	//check test-net dcrd  private address
	testnet_dcrd_private := "25FxBJ9sTySdnkNg6orjFTi6oddAVEJzZXyV"
	ret, err = AddressCheck(testnet_dcrd_private, "DCRD")
	if ret == true && err == nil {
		fmt.Println("test net dcrd private address test success!!!")
	} else {
		fmt.Println("test net dcrd private address test fail!!!")
	}
	//check simnet dcrd  p2pkh address
	simnet_dcrd_p2pkh := "SssVgPTs3N3poqmjmZ8UKsv54P5ud5hQanp"
	ret, err = AddressCheck(simnet_dcrd_p2pkh, "DCRD")
	if ret == true && err == nil {
		fmt.Println("sim net dcrd p2pkh address test success!!!")
	} else {
		fmt.Println("sim net dcrd p2pkh address test fail!!!")
	}
	//check simnet dcrd  p2pk address
	simnet_dcrd_p2pk := "2D324TvbbwMsEw9ZPvJ2djJevYAeJfEdHUgg"
	ret, err = AddressCheck(simnet_dcrd_p2pk, "DCRD")
	if ret == true && err == nil {
		fmt.Println("sim net dcrd p2pk address test success!!!")
	} else {
		fmt.Println("sim net dcrd p2pk address test fail!!!")
	}
	//check simnet dcrd  pkhedwards address
	simnet_dcrd_pkhedwards := "SezsHQ59YFe7Gt9gVnQihoPgaKyrSrrWkk8"
	ret, err = AddressCheck(simnet_dcrd_pkhedwards, "DCRD")
	if ret == true && err == nil {
		fmt.Println("sim net dcrd pkhedwards address test success!!!")
	} else {
		fmt.Println("sim net dcrd pkhedwards address test fail!!!")
	}
	//check simnet dcrd  schnorr address
	simnet_dcrd_schnorr := "SSXaAE6AF5QDWaoYJA7pSi6jrgvdGr8qoTW"
	ret, err = AddressCheck(simnet_dcrd_schnorr, "DCRD")
	if ret == true && err == nil {
		fmt.Println("sim net dcrd schnorr address test success!!!")
	} else {
		fmt.Println("sim net dcrd schnorr address test fail!!!")
	}
	//check simnet dcrd  p2sh address
	simnet_dcrd_p2sh := "ScxuF1qtesGV7RMifjK5mnbrx5PFEzsE5oK"
	ret, err = AddressCheck(simnet_dcrd_p2sh, "DCRD")
	if ret == true && err == nil {
		fmt.Println("sim net dcrd p2sh address test success!!!")
	} else {
		fmt.Println("sim net dcrd p2sh address test fail!!!")
	}
	//check nas account address
	nas_account := "n1ca94LzuLVe1DpQo8v3Z93cpDJMk1WNefA"
	ret, err = AddressCheck(nas_account, "NAS")
	if ret == true && err == nil {
		fmt.Println("nas account address test success!!!")
	} else {
		fmt.Println("nas account address test fail!!!")
	}
	//check nas smart contract address
	nas_smartcontract := "n21uk3TJC3g6t3FYtALNsdAtbqocghDXobJ"
	ret, err = AddressCheck(nas_smartcontract, "NAS")
	if ret == true && err == nil {
		fmt.Println("nas  smart contract address test success!!!")
	} else {
		fmt.Println("nas smart contract address test fail!!!")
	}
	//check main-net tron address
	mainnet_tron := "TA4Y5TxFzRWxSAy2p5q7Z4uoR69SWbgPdK"
	ret, err = AddressCheck(mainnet_tron, "TRON")
	if ret == true && err == nil {
		fmt.Println("main net tron address test success!!!")
	} else {
		fmt.Println("main net tron  address test fail!!!")
	}
	//check icx wallet address
	icx_wallet_addr := "hx684c9791784c10c419eaf9322ef42792e4979712"
	ret, err = AddressCheck(icx_wallet_addr, "ICX")
	if ret == true && err == nil {
		fmt.Println("icx wallet address test success!!!")
	} else {
		fmt.Println("icx wallet  address test fail!!!")
	}
}

func Test_ICX_Address(t *testing.T) {
	pubkey := []byte{0xD0, 0x57, 0x23, 0x40, 0x25, 0x5F, 0xC7, 0xBF, 0x6F, 0x4C, 0xC8, 0xAA, 0x5F, 0x3D, 0xB4, 0xB2, 0x2A, 0x69, 0x65, 0x37, 0xF5, 0x2D, 0x3C, 0x6A, 0x96, 0x6A, 0xDC, 0xCC, 0xF5, 0xDC, 0xB2, 0x8D, 0x78, 0x91, 0x52, 0x3E, 0x00, 0x3F, 0x30, 0x89, 0x77, 0xA8, 0x68, 0xCD, 0xEC, 0xB8, 0x8C, 0xD8, 0x63, 0x47, 0x6E, 0x32, 0xA5, 0x34, 0xD6, 0x2F, 0x84, 0xB9, 0x8D, 0xB3, 0x9F, 0x7B, 0x03, 0xB5}
	EncodeAddr := AddressEncode(pubkey, ICX_walletAddress)
	fmt.Println("ICX address:", EncodeAddr)
	DecodeAddr, err := AddressDecode(EncodeAddr, ICX_walletAddress)
	if err != nil {
		fmt.Println("ICX address decode err!!")
	} else {
		for _, b := range DecodeAddr {
			fmt.Printf("0x%x ", b)
		}
		fmt.Printf("\n")
	}
}

func Test_BTM_Address(t *testing.T) {
	hash := []byte{0x53, 0x24, 0xdd, 0x86, 0xce, 0xc0, 0x9c, 0x9b, 0xd1, 0x32, 0x53, 0xcf, 0x28, 0x8f, 0xbc, 0x9b, 0x5b, 0x65, 0xae, 0xe7}
	//bm1q2vjdmpkwczwfh5fj208j3raunddktth8cglz4h
	EncodeAddr := AddressEncode(hash, BTM_mainnetAddressBech32V0)
	fmt.Println("BTM address:", EncodeAddr)
	DecodeAddr, err := AddressDecode(EncodeAddr, BTM_mainnetAddressBech32V0)
	if err != nil {
		fmt.Println("BTM address decode err!!")
	} else {
		fmt.Println("BTM decode hash:", hex.EncodeToString(DecodeAddr))
	}
}

func Test_base58(t *testing.T) {
	alphabet := "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	//data := []byte{0x0a, 0x7e, 0x0a, 0x02, 0x96, 0xac, 0x22, 0x08, 0xdf, 0xfa, 0xf0, 0xb0, 0x25, 0xa9, 0xec, 0x23, 0x40, 0xc8, 0x84, 0xfb, 0xc3, 0xf6, 0x2c, 0x5a, 0x67, 0x08, 0x01, 0x12, 0x63, 0x0a, 0x2d, 0x74, 0x79, 0x70, 0x65, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x61, 0x70, 0x69, 0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x2e, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x66, 0x65, 0x72, 0x43, 0x6f, 0x6e, 0x74, 0x72, 0x61, 0x63, 0x74, 0x12, 0x32, 0x0a, 0x15, 0x41, 0x88, 0x76, 0x61, 0xd2, 0xe0, 0x21, 0x58, 0x51, 0x75, 0x6b, 0x1e, 0x79, 0x33, 0x21, 0x60, 0x64, 0x52, 0x6b, 0xad, 0xcd, 0x12, 0x15, 0x41, 0xb6, 0xc1, 0xab, 0xf9, 0xfb, 0x31, 0xc9, 0x07, 0x7d, 0xfb, 0x3c, 0x25, 0x46, 0x9e, 0x6e, 0x94, 0x3f, 0xfb, 0xfa, 0x7a, 0x18, 0xc0, 0x84, 0x3d, 0x95, 0x78, 0x9f, 0x3d, 0x04, 0xce, 0xfe, 0xce, 0x8e, 0x43, 0x34, 0xe5, 0xb6, 0x9e, 0x28, 0xd9, 0xfc, 0xaf, 0x05, 0x10, 0x64, 0x8e, 0xf9, 0x69, 0x45, 0x77, 0x0a, 0x34, 0x8c, 0x91, 0x2d, 0x08, 0x53, 0xb4, 0xc0, 0x40, 0x15, 0x5f, 0x2e, 0x3c, 0xc0, 0xf9, 0x45, 0x78, 0x82, 0x1a, 0x67, 0x3e, 0x7c, 0xe7, 0xeb, 0x5f, 0x0d, 0xcf, 0x4f, 0x26, 0x8d, 0xff, 0xcc, 0xee, 0x1b, 0xaa, 0xb3, 0x71, 0x00}
	//str:="Ae2tdPwUPEZKyArxpKiJu9qDf4yrBb8mJc6aNqiNi72NqRkJKTmCXHJqWVE"
	//ret,_:=Base58Decode(str, NewBase58Alphabet(ZECAlphabet))
	str := "AYKv2zdggcvRVi4z9aRy34GefCEFgibKkD"
	ret, _ := Base58Decode(str, NewBase58Alphabet(alphabet))
	fmt.Println("base58 result:", hex.EncodeToString(ret))
}
func Test_crc32(t *testing.T) {
	//msg:=[]byte{0x83,0x58,0x1c,0x92,0x85,0x2f,0xf9,0xd5,0x62,0x81,0xbc,0x20,0x25,0xcf,0xd8,0x70,0x95,0x20,0x75,0x4b,0xf3,0xed,0xd7,0xd4,0x11,0xcc,0x82,0x77,0x2f,0x22,0x00,0xa0,0x00}
	//msg:=[]byte{0x83,0x58,0x1c,0xfd,0xe5,0x7e,0xc5,0x91,0x20,0x7a,0x12,0x77,0x85,0x50,0x57,0x80,0xc3,0x20,0x1a,0xd8,0x8e,0xde,0xc7,0xae,0xfd,0xca,0x6d,0x23,0x90,0xf5,0x53,0xa1,0x01,0x58,0x1e,0x58,0x1c,0x5b,0x5f,0x35,0xb4,0x49,0xd0,0xd1,0x18,0x9f,0xf6,0xfc,0x20,0x31,0x4c,0xd6,0x23,0x46,0xe9,0xe5,0xc4,0x95,0x78,0xae,0xa9,0x31,0x06,0x83,0x1e,0x00}
	msg := []byte{0x83, 0x58, 0x1c, 0xe8, 0x22, 0x00, 0x9e, 0x78, 0x49, 0x2c, 0x1d, 0x2d, 0xbb, 0x0c, 0xaa, 0x9d, 0xd1, 0x41, 0xa0, 0x79, 0xc2, 0x65, 0x96, 0xc4, 0x83, 0xb4, 0x9d, 0x7d, 0xb7, 0xad, 0x54, 0xa0, 0x00}
	ret := CRC32(msg)
	fmt.Println("crc32 result:", hex.EncodeToString(ret))
}

func Test_hash(t *testing.T) {
	//pubkey:=[]byte{0x64,0xb2,0x0f,0xa0,0x82,0xb3,0x14,0x3d,0x6b,0x5e,0xed,0x42,0xc6,0xef,0x63,0xf9,0x95,0x99,0xd0,0x88,0x8a,0xfe,0x06,0x06,0x20,0xab,0xc1,0xb3,0x19,0x93,0x5f,0xe1,0x73,0x9f,0x4b,0x3c,0xac,0xa4,0xc9,0xad,0x4f,0xcd,0x4b,0xdc,0x2e,0xf4,0x2c,0x86,0x01,0xaf,0x8d,0x69,0x46,0x99,0x9e,0xf8,0x5e,0xf6,0xae,0x84,0xf6,0x6e,0x72,0xeb}
	//addrRoot:=[]byte{0x83,0x00,0x82,0x00,0x58,0x40,0x64,0xb2,0x0f,0xa0,0x82,0xb3,0x14,0x3d,0x6b,0x5e,0xed,0x42,0xc6,0xef,0x63,0xf9,0x95,0x99,0xd0,0x88,0x8a,0xfe,0x06,0x06,0x20,0xab,0xc1,0xb3,0x19,0x93,0x5f,0xe1,0x73,0x9f,0x4b,0x3c,0xac,0xa4,0xc9,0xad,0x4f,0xcd,0x4b,0xdc,0x2e,0xf4,0x2c,0x86,0x01,0xaf,0x8d,0x69,0x46,0x99,0x9e,0xf8,0x5e,0xf6,0xae,0x84,0xf6,0x6e,0x72,0xeb,0xa0}
	msg := []byte{0x2c, 0xcc, 0xcd, 0x27, 0x79, 0x75, 0xa5, 0xc4, 0x09, 0x35, 0x3c, 0xdb, 0xeb, 0x6c, 0x7b, 0x17, 0x35, 0x3d, 0x88, 0x36, 0x2d, 0xb5, 0xa9, 0x46, 0x47, 0x54, 0x7e, 0x19, 0x1d, 0xcf, 0x83, 0x29}
	hash := owcrypt.Hash(msg, 28, owcrypt.HASH_ALG_BLAKE2B)
	fmt.Println("sha3-256 result", hex.EncodeToString(hash))
}

func Test_ONT_address(t *testing.T) {
	addr := "ATfZt5HAHrx3Xmio3Ak9rr23SyvmgNVJqU"
	DecodeAddr, err := AddressDecode(addr, ONT_Address)
	if err != nil {
		fmt.Println("ONT address decode error!!!")
	} else {
		fmt.Println("ONT address decode result:", hex.EncodeToString(DecodeAddr))
	}
	EncodeAddr := AddressEncode(DecodeAddr, ONT_Address)
	fmt.Println("ONT address:", EncodeAddr)
}
func Test_DOGE_address(t *testing.T) {

	addr := "A9j94nULZ16Bq1zM2y4pQEDP8hpQqg8n2c"
	/*
		DecodeAddr1, err := AddressDecode(addr, DOGE_singleSignAddressP2PKH)
		if err != nil {
			fmt.Println("DOGE singleSig address decode error!!!")
		} else {
			fmt.Println("DOGE singleSig address decode result:", hex.EncodeToString(DecodeAddr1))
		}
	*/
	DecodeAddr2, err := AddressDecode(addr, DOGE_multiSignAddressP2PKH)
	if err != nil {
		fmt.Println("DOGE multiSig address decode error!!!")
	} else {
		fmt.Println("DOGE multiSig address decode result:", hex.EncodeToString(DecodeAddr2))
	}

	//hash := []byte{0xA4, 0x52, 0x41, 0xEF, 0x8F, 0xB2, 0x99, 0x41, 0xB9, 0x10, 0xB4, 0xE9, 0x40, 0x03, 0x5E, 0x91, 0x7F, 0x5D, 0x70, 0x13}
	//EncodeAddr1 := AddressEncode(hash, DOGE_multiSignAddressP2PKH)
	//fmt.Println("singleSign address:", EncodeAddr1)
	//EncodeAddr2 := AddressEncode(hash, DOGE_singleSignAddressP2PKH)
	//fmt.Println("singleSign address:", EncodeAddr2)

}

func Test_xmrAddress(t *testing.T) {
	//----------test mainnet public address------------
	// pubKey := []byte{0x95, 0xee, 0xff, 0x6f, 0xbc, 0x5f, 0x0b, 0x9f, 0xcf, 0xf1, 0xf5, 0xb4, 0x95, 0x54, 0x70, 0xd4, 0x8e, 0x51, 0x9e, 0x04, 0x43, 0x5e, 0xb0, 0xd7, 0xf6, 0x9b, 0x83, 0x7d, 0x1c, 0xb0, 0x1a, 0xcb, 0xdd, 0xdc, 0xfb, 0x5e, 0x38, 0xf4, 0xd8, 0x17, 0x21, 0xa9, 0x55, 0x0e, 0xc7, 0x40, 0x37, 0x63, 0xdf, 0x66, 0xf2, 0x9f, 0x7b, 0x32, 0x3b, 0x1c, 0x00, 0x03, 0xb4, 0x2e, 0x3e, 0x6c, 0x19, 0x6f}
	// if len(pubKey) != 64 {
	// 	fmt.Println("ERR!!!")
	// }
	// addrRet := AddressEncode(pubKey, XMR_mainnetPublicAddress)
	// fmt.Println("xmr mainnet addr", addrRet)
	// hash, err := AddressDecode(addrRet, XMR_mainnetPublicAddress)
	// if err != nil {
	// 	fmt.Println("decode addr is error!!!")
	// } else {
	// 	fmt.Println("hash result:", hex.EncodeToString(hash))
	// }
	//-----------end---------------

	//----------test testnet address---------
	// pubKey := []byte{0x79, 0xb7, 0x44, 0x59, 0x08, 0x12, 0xba, 0xe5, 0x60, 0xac, 0x81, 0x3c, 0xd2, 0xf9, 0x1c, 0x15, 0x93, 0x0d, 0x2b, 0x63, 0x94, 0x93, 0xee, 0x50, 0x4b, 0xd6, 0x3d, 0xfa, 0xd7, 0xee, 0xad, 0xcc, 0x34, 0x89, 0x8a, 0xe9, 0x6e, 0xc8, 0xcb, 0x0e, 0xa0, 0x3c, 0xf1, 0x9e, 0x1a, 0xda, 0xb2, 0xdb, 0xb5, 0x4c, 0x1b, 0xcd, 0x2c, 0x44, 0x61, 0x84, 0x42, 0x24, 0xa2, 0x38, 0x82, 0x7a, 0x9b, 0x9c}
	// //9wnB9GVRBR3fNFXDk9L2Cb4cJLVFuJFbTERyVqfFJhk8bA3hKUncxVG3StcRkiEm3PdkSnvWHyAVeP85Ao4XK4GzJfMJn5R
	// addrRet := AddressEncode(pubKey, XMR_testnetPublicAddress)
	// fmt.Println("xmr testnet public addr", addrRet)
	// hash, err := AddressDecode(addrRet, XMR_testnetPublicAddress)
	// if err != nil {
	// 	fmt.Println("decode addr is error!!!")
	// } else {
	// 	fmt.Println("hash result:", hex.EncodeToString(hash))
	// }
	//---------end--------------
	//---------test mainnet public sub address----------
	//pubKey := []byte{0x33, 0xe2, 0x0d, 0x8d, 0x8e, 0x48, 0xc1, 0xba, 0x7d, 0xf3, 0x8f, 0xff, 0x39, 0x9d, 0x78, 0xf4, 0xe9, 0x03, 0xc6, 0xb9, 0x1a, 0x30, 0x62, 0x88, 0xb7, 0x00, 0x60, 0x58, 0x64, 0xbd, 0x48, 0x72, 0x28, 0x70, 0xbe, 0xa1, 0x56, 0xd1, 0xa9, 0x5c, 0x56, 0x2b, 0x72, 0x85, 0xff, 0x3b, 0xd3, 0x48, 0x91, 0xc3, 0x05, 0xbf, 0xa6, 0x53, 0x2e, 0x52, 0xd2, 0xdc, 0x33, 0xa9, 0xb7, 0xfd, 0xcd, 0xeb}
	//84RHfDp8GtGYCCwwamE4vbhxwHEpUkEC9PsJi1vcLqWoL6UZxAR8wckGSnHEyU1ccAD91oo22CEGDErVchuBhZeCTWwjqNk
	// addrRet := AddressEncode(pubKey, XMR_mainnetPublicSubAddress)
	// fmt.Println("xmr mainnet public sub addr:", addrRet)
	// hash, err := AddressDecode(addrRet, XMR_mainnetPublicSubAddress)
	// if err != nil {
	// 	fmt.Println("decode addr is error!!!")
	// } else {
	// 	fmt.Println("hash result:", hex.EncodeToString(hash))
	// }
	//---------test mainnet public integrated address---------
	pubKey := []byte{0x1d, 0x51, 0x78, 0x04, 0x9a, 0xef, 0xb9, 0x82, 0x91, 0x91, 0x6f, 0x80, 0x46, 0xfd, 0x23, 0x01, 0x82, 0x3c, 0xcb, 0x9d, 0xff, 0xfe, 0xc2, 0x5a, 0x20, 0x32, 0x1d, 0x7d, 0xa3, 0x84, 0x2a, 0x4e, 0x87, 0xe8, 0x29, 0x1d, 0x50, 0x6b, 0xa5, 0x11, 0xa0, 0xf1, 0x62, 0x9d, 0xb7, 0x55, 0x1d, 0x38, 0x51, 0x40, 0x33, 0xdc, 0x50, 0xf7, 0x0a, 0x16, 0xc1, 0x2f, 0x87, 0xfe, 0x7f, 0xfc, 0xde, 0x1f, 0xaf, 0xfc, 0xaf, 0xbf, 0xf1, 0x83, 0x59, 0x82}
	//4CSDmauDZx4NqgPueqKeTU1Fdvks1goHKG5LJawiP6JVE8rBZnzDwoJ3x2BKjs9VA4ARMFg2CEZo74okQiYg1GYm6JQfMWAyC2cFjjkbLT
	addrRet := AddressEncode(pubKey, XMR_mainnetPublicIntegratedAddress)
	fmt.Println("xmr mainnet public integrated address:", addrRet)
	hash, err := AddressDecode(addrRet, XMR_mainnetPublicIntegratedAddress)
	if err != nil {
		fmt.Println("decode addr is error!!!")
	} else {
		fmt.Println("hash result:", hex.EncodeToString(hash))
	}
	//----------------------------end--------------------------
}

func Test_VSYSAddress(t *testing.T) {
	pubkey, _ := hex.DecodeString("a9d59feec551438cc7437e39cd75328bc0c345bfc8fc918843c2548772ba2640")
	hash := owcrypt.Hash(pubkey, 32, owcrypt.HASH_ALG_BLAKE2B)
	hash = owcrypt.Hash(hash, 32, owcrypt.HASH_ALG_KECCAK256)[:20]
	fmt.Println(hex.EncodeToString(hash))

	address := AddressEncode(hash, VSYS_mainnetAddress)

	fmt.Println(address)
	if address != "ARQEGuxzau9ZSsPgWWHNJYgVPUxJYQeGb4F" {
		t.Error("vsys address encode failed")
	} else {
		fmt.Println(address)
	}

	chk, err := AddressDecode(address, VSYS_mainnetAddress)

	if err != nil {
		t.Error("vsys address decode failed!")
	} else {
		fmt.Println(hex.EncodeToString(chk))
	}
}

func Test_TVAddress(t *testing.T) {
	pubkey, _ := hex.DecodeString("4c6efab3d1e53892eb5aa3c62a5c76c3af7dea5e66c1243741d70d42d5ac5d06")
	hash := owcrypt.Hash(pubkey, 32, owcrypt.HASH_ALG_BLAKE2B)
	hash = owcrypt.Hash(hash, 32, owcrypt.HASH_ALG_KECCAK256)[:20]
	fmt.Println(hex.EncodeToString(hash))

	address := AddressEncode(hash, TV_mainnetAddress)

	fmt.Println(address)
}

func Test_EOSAddress(t *testing.T) {
	pubkey, _ := hex.DecodeString("02c0ded2bc1f1305fb0faac5e6c03ee3a1924234985427b6167ca569d13df435cf")
	address := AddressEncode(pubkey, EOS_mainnetPublic)

	fmt.Println(address)
	if address != "EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV" {
		t.Error("eos address encode failed")
		return
	} else {
		fmt.Println(address)
	}

	chk, err := AddressDecode(address, EOS_mainnetPublic)
	if err != nil {
		t.Errorf("eos address decode failed! err: %v \n", err)
		return
	} else {
		fmt.Println(hex.EncodeToString(chk))
	}

	prvkey, _ := hex.DecodeString("62491722c73af9a130baf583d80c03830df6b7a3d5c042a0048c31b095fe0d96")
	wif := AddressEncode(prvkey, EOS_mainnetPrivateWIF)
	if wif != "5JZa9piFEu5GkRvDw2gb7jqDwy6r1Bi6cDStKChuEqWGWpvXdao" {
		t.Error("eos wif encode failed")
		return
	} else {
		fmt.Println(wif)
	}

	chp, err := AddressDecode(wif, EOS_mainnetPrivateWIF)
	if err != nil {
		t.Errorf("eos wif decode failed! err: %v \n", err)
		return
	} else {
		fmt.Println(hex.EncodeToString(chp))
	}

}

func Test_AEAddress(t *testing.T) {
	pubkey, _ := hex.DecodeString("6e6490ba9ffa3ed276048e23c52f09a7622e02111124e9c770d1a6ac11a723c6")
	address := AddressEncode(pubkey, AE_mainnetAddress)

	fmt.Println(address)
	if address != "ak_qcqXt6ySgRPvBkNwEpNMvaKWzrhPZsoBHLvgg68qg9vRht62y" {
		t.Error("eos address encode failed")
		return
	} else {
		fmt.Println(address)
	}

	chk, err := AddressDecode(address, AE_mainnetAddress)
	if err != nil {
		t.Errorf("eos address decode failed! err: %v \n", err)
		return
	} else {
		fmt.Println(hex.EncodeToString(chk))
	}

}

func Test_ATOMAddress(t *testing.T) {
	hash, _ := hex.DecodeString("3335a8768bf87fbd1e554e71a82da2809110e190")
	address := AddressEncode(hash, ATOM_mainnetAddress)

	if address != "cosmos1xv66sa5tlplm68j4fec6stdzszg3pcvswag06j" {
		t.Error("atom address encode failed!")
	} else {
		fmt.Println("atom address encode success!")
		fmt.Println(address)
	}

	check, err := AddressDecode(address, ATOM_mainnetAddress)
	if err != nil {
		t.Error("atom address decode failed!")
	} else {
		for index := 0; index < 20; index++ {
			if check[index] != hash[index] {
				t.Error("atom address decode failed!")
			}
		}
		fmt.Println("atom address decode success!")
	}
}

func Test_ELA_Address(t *testing.T) {
	address := "Eb1r8zaS3qbsRFH4j4GADshJCqFZ84ZM8u"

	hash, err := AddressDecode(address, ELA_Address)
	if err != nil {
		t.Error(err)
	} else {
		if hex.EncodeToString(hash) != "c3ec22c32fd1f5a14cb6467c7b7728f34a6b3d76" {
			t.Error("ela address decode failed!")
		}
	}

	chk := AddressEncode(hash, ELA_Address)
	if chk != address {
		t.Error("ela address encode failed!")
	}
}

func Test_BNB_Address(t *testing.T) {
	address := "bnb1p89xmrejmqpwmkye4z2pwtrw49n2vykf3nax33"

	hash, err := AddressDecode(address, BNB_mainnetAddress)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Println(hex.EncodeToString(hash))
	}

	check := AddressEncode(hash, BNB_mainnetAddress)

	if check != address {
		t.Error(err)
	}
}

func Test_ltc_new_address(t *testing.T) {
	hash := []byte{0x53, 0x24, 0xdd, 0x86, 0xce, 0xc0, 0x9c, 0x9b, 0xd1, 0x32, 0x53, 0xcf, 0x28, 0x8f, 0xbc, 0x9b, 0x5b, 0x65, 0xae, 0xe7}

	address := AddressEncode(hash, LTC_mainnetAddressP2SH)
	fmt.Println(address)

	address = AddressEncode(hash, LTC_mainnetAddressP2SH2)
	fmt.Println(address)

	check, err := AddressDecode("ltc1q5c9vun5ctq377nfkznaxlj7nh5a0esm90n89t7", LTC_mainnetAddressBech32V0)
	fmt.Println(err)
	fmt.Println(hex.EncodeToString(check))
}
