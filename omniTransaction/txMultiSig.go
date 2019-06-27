package omniTransaction

import (
	"encoding/hex"
	"errors"

	owcrypt "github.com/blocktree/go-owcrypt"
)

// type msSigPub struct {
// 	sig []byte
// 	pub []byte
// }

type txMultiSig struct {
	nRequired byte
	sigPub    []SignaturePubkey
}

func CreateMultiSig(required byte, pubkeys [][]byte, addressPrefix AddressPrefix) (string, string, error) {
	if required < 1 {
		return "", "", errors.New("A multisignature address must require at least one key to redeem!")
	}
	if required > byte(len(pubkeys)) {
		return "", "", errors.New("Not enough keys supplied for a multisignature address to redeem!")
	}
	if len(pubkeys) > 16 {
		return "", "", errors.New("Number of keys involved in the multisignature address creation is too big!")
	}

	redeem := []byte{}

	redeem = append(redeem, OpCode_1+required-1)

	for _, k := range pubkeys {
		if len(k) != 33 && len(k) != 65 {
			return "", "", errors.New("Invalid pubkey data for multisignature address!")
		}
		redeem = append(redeem, byte(len(k)))
		redeem = append(redeem, k...)
	}

	redeem = append(redeem, OpCode_1+byte(len(pubkeys))-1)

	redeem = append(redeem, OpCheckMultiSig)

	if len(redeem) > MaxScriptElementSize {
		return "", "", errors.New("Redeem script exceeds size limit!")
	}
	var redeemHash []byte
	if false {
		redeemHash = owcrypt.Hash(redeem, 0, owcrypt.HASH_ALG_SHA256)
		redeemHash = append([]byte{0x00, 0x20}, redeemHash...)
		redeemHash = owcrypt.Hash(redeemHash, 0, owcrypt.HASH_ALG_HASH160)
	} else {
		redeemHash = owcrypt.Hash(redeem, 0, owcrypt.HASH_ALG_HASH160)
	}
	return EncodeCheck(addressPrefix.P2PKHPrefix, redeemHash), hex.EncodeToString(redeem), nil
}

func getMultiDetails(redeem []byte) (byte, []string, error) {
	pubkeys := []string{}
	limit := len(redeem)
	index := 0
	if index+1 > limit {
		return 0, nil, errors.New("Invalid redeem script for multisig UTXO!")
	}
	nRequired := redeem[index] + 1 - OpCode_1
	index++

	if nRequired <= 0 || nRequired > 16 {
		return 0, nil, errors.New("Required number is invalid for a multisig redeem!")
	}

	for {
		if index+1 > limit {
			return 0, nil, errors.New("Invalid redeem script for multisig UTXO!")
		}
		if redeem[index] != 0x21 {
			break
		}
		index++
		if index+0x21 > limit {
			return 0, nil, errors.New("Invalid redeem script for multisig UTXO!")
		}
		pubkeys = append(pubkeys, hex.EncodeToString(redeem[index:index+0x21]))
		index += 0x21
	}

	if index+1 > limit {
		return 0, nil, errors.New("Invalid redeem script for multisig UTXO!")
	}
	total := redeem[index] + 1 - OpCode_1

	if total != byte(len(pubkeys)) || total < nRequired {
		return 0, nil, errors.New("Invalid redeem script for multisig UTXO!")
	}

	return nRequired, pubkeys, nil
}

func decodeMultiBytes(script []byte) ([]SignaturePubkey, []byte, error) {

	var sp []SignaturePubkey
	var st []byte
	if script == nil || len(script) == 0 {
		return nil, nil, errors.New("Invalid multisig script data!")
	}
	limit := len(script)
	index := 0
	length := 0

	if index+1 > limit {
		return nil, nil, errors.New("Invalid multisig script data!")
	}

	if script[index] == 0 {

	} else if script[index] == 0xFD {
		index++
		if index+2 > limit {
			return nil, nil, errors.New("Invalid multisig script data!")
		}
		length = int(littleEndianBytesToUint16(script[index : index+2]))
		index += 2
		if length+3 != limit {
			return nil, nil, errors.New("Invalid multisig script data!")
		}
	} else {
		length = int(script[index])
		index++

		if length+1 != limit {
			return nil, nil, errors.New("Invalid multisig script data!")
		}
	}
	if script[index] != 0x00 {
		return nil, nil, errors.New("Invalid multisig script data!")
	}
	index++

	for {
		if index+2 > limit {
			return nil, nil, errors.New("Invalid multisig script data!")
		}
		sigLen := script[index]
		if script[index+1] != 0x30 {
			break
		}
		if index+int(sigLen)+1 > limit {
			return nil, nil, errors.New("Invalid multisig script data!")
		}
		sig, sigType, err := decodeSignatureFromScript(script[index : index+int(sigLen)+1])
		if err != nil {
			return nil, nil, err
		}
		sp = append(sp, SignaturePubkey{sig, nil})
		st = append(st, sigType)
		index += int(sigLen + 1)
	}
	if index+1 > limit {
		return nil, nil, errors.New("Invalid multisig script data!")
	}
	redeemLen := 0
	if script[index] == OpPushData1 {
		index++
		if index+1 > limit {
			return nil, nil, errors.New("Invalid multisig script data!")
		}
		redeemLen = int(script[index])
		index++
	} else if script[index] == OpPushData2 {
		index++
		if index+2 > limit {
			return nil, nil, errors.New("Invalid multisig script data!")
		}
		redeemLen = int(littleEndianBytesToUint16(script[index : index+2]))
		index += 2
	} else {
		redeemLen = int(script[index])
		index++
	}

	if index+1 > limit {
		return nil, nil, errors.New("Invalid multisig script data!")
	}
	required := script[index] + 1 - OpCode_1
	index++

	if int(required) != len(sp) {
		return nil, nil, errors.New("Multisig not completely signed!")
	}

	if index+int(redeemLen)-1 != limit {
		return nil, nil, errors.New("Invalid multisig script data!")
	}

	if script[len(script)-1] != OpCheckMultiSig {
		return nil, nil, errors.New("Invalid multisig script data!")
	}
	pubkeys := int(script[len(script)-2]) + 1 - int(OpCode_1)
	pscript := script[index : len(script)-2]

	if pubkeys > len(sp) {
		for i := 0; i < pubkeys-len(sp); i++ {
			sp = append(sp, SignaturePubkey{nil, nil})
			st = append(st, 0)
		}
	}

	index = 0
	limit = redeemLen
	for i := 0; i < pubkeys; i++ {
		if index+1 > limit {
			return nil, nil, errors.New("Invalid multisig script data!")
		}
		if pscript[index] != 0x21 {
			return nil, nil, errors.New("Invalid multisig script data!")
		}
		index++
		if index+0x21 > limit {
			return nil, nil, errors.New("Invalid multisig script data!")
		}
		sp[i].Pubkey = pscript[index : index+0x21]
		index += 0x21
	}

	return sp, st, nil
}
