package signatureSet

import (
	"fmt"
	"github.com/blocktree/go-owcdrivers/btcTransaction"
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

	if strings.EqualFold(symbol, "ETH") {
		sig, err := EthSignature(privateKey, msg)
		if err != owcrypt.SUCCESS {
			return nil, fmt.Errorf("ETH sign hash failed")
		}
		return sig, nil
	}

	if strings.EqualFold(symbol, "TRUE") {
		sig, err := EthSignature(privateKey, msg)
		if err != owcrypt.SUCCESS {
			return nil, fmt.Errorf("ETH sign hash failed")
		}
		return sig, nil
	}

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

func serilizeS(sig []byte) []byte {
	s := sig[32:]
	numS := new(big.Int).SetBytes(s)
	numHalfOrder := new(big.Int).SetBytes(btcTransaction.HalfCurveOrder)
	if numS.Cmp(numHalfOrder) > 0 {
		numOrder := new(big.Int).SetBytes(btcTransaction.CurveOrder)
		numS.Sub(numOrder, numS)

		return append(sig[:32], numS.Bytes()...)
	}
	return sig
}
