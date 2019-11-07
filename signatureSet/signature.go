package signatureSet

import (
	"fmt"
	"github.com/blocktree/go-owcrypt"
	"math/big"
	"strings"
)

//signTxHash 签名交易单哈希
func SignTxHash(symbol string, msg []byte, privateKey []byte, eccType uint32) ([]byte, error) {
	var sig []byte
	var sigErr uint16

	//查找是否有注册交易签名工具
	signer := GetTxSigner(symbol)
	if signer != nil {
		return signer.SignTransactionHash(msg, privateKey, eccType)
	}

	//if strings.EqualFold(symbol, "ETH") {
	//	sig, err := EthSignature(privateKey, msg)
	//	if err != owcrypt.SUCCESS {
	//		return nil, fmt.Errorf("ETH sign hash failed")
	//	}
	//	return sig, nil
	//}
	//
	//if strings.EqualFold(symbol, "TRUE") {
	//	sig, err := EthSignature(privateKey, msg)
	//	if err != owcrypt.SUCCESS {
	//		return nil, fmt.Errorf("ETH sign hash failed")
	//	}
	//	return sig, nil
	//}

	if strings.EqualFold(symbol, "NAS") {
		sig, err := NasSignature(privateKey, msg)
		if err != owcrypt.SUCCESS {
			return nil, fmt.Errorf("NAS sign hash failed")
		}
		return sig, nil
	}

	//if strings.EqualFold(symbol, "VSYS") {
	//	sig, err := VSYSSignature(privateKey, msg)
	//	if err != owcrypt.SUCCESS {
	//		return nil, fmt.Errorf("VSYS sign hash failed")
	//	}
	//	return sig, nil
	//}

	if strings.EqualFold(symbol, "TRX") {
		sig, err := TronSignature(privateKey, msg)
		if err != owcrypt.SUCCESS {
			return nil, fmt.Errorf("TRX sign hash failed")
		}
		return sig, nil
	}

	if eccType == owcrypt.ECC_CURVE_SECP256K1 {
		sig, sigErr = owcrypt.Signature(privateKey, nil, 0, msg, uint16(len(msg)), eccType)
		if sigErr != owcrypt.SUCCESS {
			return nil, fmt.Errorf("ECC sign hash failed")
		}
		sig = serilizeS(sig)
	} else {
		sig, sigErr = owcrypt.Signature(privateKey, nil, 0, msg, uint16(len(msg)), eccType)
		if sigErr != owcrypt.SUCCESS {
			return nil, fmt.Errorf("ECC sign hash failed")
		}

	}
	return sig, nil
}

var (
	CurveOrder     = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41}
	HalfCurveOrder = []byte{0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0}
)

func serilizeS(sig []byte) []byte {
	s := sig[32:]
	numS := new(big.Int).SetBytes(s)
	numHalfOrder := new(big.Int).SetBytes(HalfCurveOrder)
	if numS.Cmp(numHalfOrder) > 0 {
		numOrder := new(big.Int).SetBytes(CurveOrder)
		numS.Sub(numOrder, numS)

		s = numS.Bytes()
		if len(s) < 32 {
			for i := 0; i < 32-len(s); i++ {
				s = append([]byte{0x00}, s...)
			}
		}
		return append(sig[:32], s...)
	}
	return sig
}
