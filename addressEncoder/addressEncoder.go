package addressEncoder

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/blocktree/go-owcdrivers/addressEncoder/bech32m"
	"strings"

	"github.com/blocktree/go-owcdrivers/addressEncoder/base32PolyMod"
	"github.com/blocktree/go-owcdrivers/addressEncoder/bech32"
	"github.com/blocktree/go-owcdrivers/addressEncoder/blake256"
	"github.com/blocktree/go-owcdrivers/addressEncoder/eip55"
	"github.com/blocktree/go-owcrypt"
)

var (
	ErrorInvalidHashLength = errors.New("Invalid hash length!")
	ErrorInvalidAddress    = errors.New("Invalid address!")
)

// CalcChecksum return calculated checksum
func CalcChecksum(data []byte, chkType string) []byte {
	return calcChecksum(data, chkType)
}

func calcChecksum(data []byte, chkType string) []byte {
	if chkType == "doubleSHA256" {
		return owcrypt.Hash(data, 0, owcrypt.HASH_ALG_DOUBLE_SHA256)[:4]
	}
	if chkType == "doubleBlake256" {
		return blake256.DoubleBlake256(data)[:4]
	}
	if chkType == "keccak256" {
		return owcrypt.Hash(data, 0, owcrypt.HASH_ALG_KECCAK256)[:4]
	}
	if chkType == "sha3_256" {
		return owcrypt.Hash(data, 0, owcrypt.HASH_ALG_SHA3_256)[:4]
	}
	if chkType == "blake2b_and_keccak256_first_twenty" {
		return owcrypt.Hash(owcrypt.Hash(data, 32, owcrypt.HASH_ALG_BLAKE2B), 32, owcrypt.HASH_ALG_KECCAK256)[:4]
	}
	if chkType == "ripemd160" {
		return owcrypt.Hash(data, 0, owcrypt.HASH_ALG_RIPEMD160)[:4]
	}
	return nil
}

// VerifyChecksum return checksum result
func VerifyChecksum(data []byte, chkType string) bool {
	return verifyChecksum(data, chkType)
}

func verifyChecksum(data []byte, chkType string) bool {
	if len(data) < 4 {
		return false
	}
	checksum := calcChecksum(data[:len(data)-4], chkType)
	for i := 0; i < 4; i++ {
		if checksum[i] != data[len(data)-4+i] {
			return false
		}
	}
	return true
}

// CatData cat two bytes data
func CatData(data1 []byte, data2 []byte) []byte {
	return catData(data1, data2)
}

func catData(data1 []byte, data2 []byte) []byte {
	if data2 == nil {
		return data1
	}
	return append(data1, data2...)
}

func recoverData(data, prefix, suffix []byte) ([]byte, error) {
	for i := 0; i < len(prefix); i++ {
		if data[i] != prefix[i] {
			return nil, ErrorInvalidAddress
		}
	}
	if suffix != nil {
		for i := 0; i < len(suffix); i++ {
			if data[len(data)-len(suffix)+i] != suffix[i] {
				return nil, ErrorInvalidAddress
			}
		}
	}
	if suffix == nil {
		return data[len(prefix):], nil
	}
	return data[len(prefix) : len(data)-len(suffix)], nil
}

// EncodeData return encoded data
func EncodeData(data []byte, encodeType string, alphabet string) string {
	return encodeData(data, encodeType, alphabet)
}

func encodeData(data []byte, encodeType string, alphabet string) string {
	if encodeType == "base58" {
		return Base58Encode(data, NewBase58Alphabet(alphabet))
	}
	return ""
}

// DecodeData return decoded data
func DecodeData(data, encodeType, alphabet, checkType string, prefix, suffix []byte) ([]byte, error) {
	return decodeData(data, encodeType, alphabet, checkType, prefix, suffix)
}

func decodeData(data, encodeType, alphabet, checkType string, prefix, suffix []byte) ([]byte, error) {
	if encodeType == "base58" {
		ret, err := Base58Decode(data, NewBase58Alphabet(alphabet))
		if err != nil {
			return nil, ErrorInvalidAddress
		}
		if verifyChecksum(ret, checkType) == false {
			return nil, ErrorInvalidAddress
		}
		return recoverData(ret[:len(ret)-4], prefix, suffix)
	}
	return nil, nil
}

func calcHash(data []byte, hashType string) []byte {
	if hashType == "h160" {
		return owcrypt.Hash(data, 0, owcrypt.HASH_ALG_HASH160)
	}
	if hashType == "blake2b160" {
		return owcrypt.Hash(data, 20, owcrypt.HASH_ALG_BLAKE2B)
	}
	if hashType == "ripemd160" {
		return owcrypt.Hash(data, 20, owcrypt.HASH_ALG_RIPEMD160)
	}
	if hashType == "keccak256_ripemd160" {
		return owcrypt.Hash(data, 0, owcrypt.HASH_ALG_KECCAK256_RIPEMD160)
	}
	if hashType == "sha3_256_ripemd160" {
		return owcrypt.Hash(data, 0, owcrypt.HASH_ALG_SHA3_256_RIPEMD160)
	}
	if hashType == "keccak256" {
		return owcrypt.Hash(data, 32, owcrypt.HASH_ALG_KECCAK256)
	}
	if hashType == "sha3_256_last_twenty" {
		return owcrypt.Hash(data, 32, owcrypt.HASH_ALG_SHA3_256)[12:32]
	}
	if hashType == "keccak256_last_twenty" {
		return owcrypt.Hash(data, 32, owcrypt.HASH_ALG_KECCAK256)[12:32]
	}
	if hashType == "blake2b_and_keccak256_first_twenty" {
		return owcrypt.Hash(owcrypt.Hash(data, 32, owcrypt.HASH_ALG_BLAKE2B), 32, owcrypt.HASH_ALG_KECCAK256)[:20]
	}
	return nil
}

func AddressEncode(hash []byte, addresstype AddressType) string {

	if addresstype.EncodeType == "bech32m" {
		address, err := bech32m.Bech32mEncode(addresstype.ChecksumType, hash, addresstype.Alphabet)
		if err != nil {
			return ""
		}
		return  address
	}

	if addresstype.EncodeType == "bech32" {
		return bech32.Encode(addresstype.ChecksumType, addresstype.Alphabet, hash, addresstype.Prefix)
	}

	if len(hash) != addresstype.HashLen {
		hash = calcHash(hash, addresstype.HashType)
	}

	if addresstype.EncodeType == "base32PolyMod" {
		return base32PolyMod.Encode(addresstype.ChecksumType, addresstype.Alphabet, hash)
	}
	if addresstype.EncodeType == "eip55" {
		return eip55.Eip55_encode(hash)
	}
	if addresstype.EncodeType == "ICX" {
		return addresstype.ChecksumType + hex.EncodeToString(hash[:])
	}
	if addresstype.EncodeType == "XMR" {
		if addresstype.HashType == "" {
			//hash = public spend key(32-byte)||public view key(32 byte),total 64 bytes
			if len(hash) != 64 {
				fmt.Println("hash length is error,not 64!!!")
				return ""
			}
		}
		if addresstype.HashType == "payID" {
			//hash=public spend key(32 byte)||public view key(32 byte)||payID(8 byte),total 72 bytes
			if len(hash) != 72 {
				fmt.Println("hash length is error,not 72!!!")
				return ""
			}
		}
		//addPrefixHash = Prefix||hash=prxfix || public sepend key||public view key(65-byte)
		addPrefixHash := append(addresstype.Prefix, hash...)
		//checksum is the first four bytes of keccak256(addPrefixHash)
		checksum := owcrypt.Hash(addPrefixHash, 32, owcrypt.HASH_ALG_KECCAK256)[:4]
		//Suffix checksum addPrefixHash(69-byte)
		addPrefixHashSuffix := append(addPrefixHash, checksum...)
		//Separed addPrefixHashSuffix 8 blocks whose length is 8-byte.  Convered Base58 characters for each block.
		//If the length of characters less than 11,the conversion pads it with “1”s(1 is 0 in Base58)
		//The final 5-byte block can conver 7 or less Base58 digits and the conversion will ensure the result is 7 digits.
		//Total 95 Base58 characters
		var EncodeRet string
		cycle := len(addPrefixHashSuffix) >> 3
		remainder := len(addPrefixHashSuffix) - (cycle << 3)
		for i := 0; i < cycle; i++ {
			blockBuf := addPrefixHashSuffix[(i << 3):((i + 1) << 3)]
			blockBase58 := Base58Encode(blockBuf, NewBase58Alphabet(addresstype.Alphabet))
			if len(blockBase58) < 11 {
				cycle := 11 - len(blockBase58)
				for j := 0; j < cycle; j++ {
					blockBase58 = "1" + blockBase58
				}
			}
			EncodeRet += blockBase58
		}
		lastBlockBase58 := Base58Encode(addPrefixHashSuffix[cycle<<3:(cycle<<3)+remainder], NewBase58Alphabet(addresstype.Alphabet))
		if len(lastBlockBase58) < 7 {
			cycle := 7 - len(lastBlockBase58)
			for j := 0; j < cycle; j++ {
				lastBlockBase58 = "1" + lastBlockBase58
			}
		}
		EncodeRet += lastBlockBase58
		return EncodeRet
	}

	if strings.EqualFold(addresstype.EncodeType, "eos") {
		return encodeEOS(hash, addresstype)
	}

	if strings.EqualFold(addresstype.EncodeType, "aeternity") {
		return encodeAE(hash, addresstype)
	}

	data := catData(catData(addresstype.Prefix, hash), addresstype.Suffix)
	return encodeData(catData(data, calcChecksum(data, addresstype.ChecksumType)), addresstype.EncodeType, addresstype.Alphabet)

}

func AddressDecode(address string, addresstype AddressType) ([]byte, error) {

	if addresstype.EncodeType == "bech32m" {
		return bech32m.Bech32mDecode(address, addresstype.ChecksumType, addresstype.Alphabet)
	}

	if addresstype.EncodeType == "bech32" {
		ret, err := bech32.Decode(address, addresstype.Alphabet)
		if err != nil {
			return nil, ErrorInvalidAddress
		}
		if len(ret) != 20 && len(ret) != 32 {
			return nil, ErrorInvalidHashLength
		}
		return ret, nil
	}
	if addresstype.EncodeType == "base32PolyMod" {
		ret, err := base32PolyMod.Decode(address, addresstype.Alphabet)
		if err != nil {
			return nil, ErrorInvalidAddress
		}
		if len(ret) != addresstype.HashLen {
			return nil, ErrorInvalidHashLength
		}
		return ret, nil
	}
	if addresstype.EncodeType == "eip55" {
		ret, err := eip55.Eip55_decode(address)
		if err != nil {
			return nil, ErrorInvalidAddress
		}
		if len(ret) != 20 {
			return nil, ErrorInvalidHashLength
		}
		return ret, nil
	}
	if addresstype.EncodeType == "ICX" {
		if address[0] != 'h' || address[1] != 'x' {
			return nil, ErrorInvalidAddress
		} else {
			if len(address)-2 != 40 {
				return nil, ErrorInvalidHashLength
			} else {
				ret, err := hex.DecodeString(address[2:])
				if err != nil {
					return nil, err
				}
				return ret, nil
			}
		}
	}
	if addresstype.EncodeType == "XMR" {
		if addresstype.HashType == "" {
			if len(address) != 95 {
				return nil, fmt.Errorf("address length is not 95,error!!!")
			}
		}
		if addresstype.HashType == "payID" {
			if len(address) != 106 {
				return nil, fmt.Errorf("address length is not 106,error!!!")
			}
		}
		var decodeRet []byte
		cycle := len(address) / 11
		remainder := len(address) - (cycle * 11)
		for i := 0; i < cycle; i++ {
			blockAddr := address[i*11 : (i+1)*11]
			blockDecode, err := Base58Decode(blockAddr, NewBase58Alphabet(addresstype.Alphabet))
			if err != nil {
				fmt.Printf("Base58 decode failed,block:%d,unexpected error:%v", i+1, err)
				return nil, err
			}
			if len(blockDecode) < 8 {
				return nil, fmt.Errorf("decode result length error,block:%d", i+1)
			} else {
				decodeRet = append(decodeRet, blockDecode[len(blockDecode)-8:]...)
			}
		}
		lastBlockDecode, err := Base58Decode(address[(cycle*11):(cycle*11+remainder)], NewBase58Alphabet(addresstype.Alphabet))
		if err != nil {
			fmt.Printf("The last block decode failed,unexpected error:%v", err)
			return nil, err
		}
		if len(lastBlockDecode) < 5 {
			return nil, fmt.Errorf("The last block decode result length error!!!")
		} else {
			decodeRet = append(decodeRet, lastBlockDecode[len(lastBlockDecode)-5:]...)
		}
		if verifyChecksum(decodeRet, addresstype.ChecksumType) == false {
			fmt.Printf("verify address checksum failed!!!")
			return nil, ErrorInvalidAddress
		}
		ret, err := recoverData(decodeRet[:len(decodeRet)-4], addresstype.Prefix, addresstype.Suffix)
		if err != nil {
			fmt.Printf("recover data failed!!!")
			return nil, err
		}
		return ret, nil
	}

	if strings.EqualFold(addresstype.EncodeType, "eos") {
		return decodeEOS(address, addresstype)
	}

	if strings.EqualFold(addresstype.EncodeType, "aeternity") {
		return decodeAE(address, addresstype)
	}

	data, err := decodeData(address, addresstype.EncodeType, addresstype.Alphabet, addresstype.ChecksumType, addresstype.Prefix, addresstype.Suffix)
	if err != nil {
		return nil, err
	}
	if len(data) != addresstype.HashLen {
		return nil, ErrorInvalidHashLength
	}
	return data, nil
}
