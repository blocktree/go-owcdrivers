package signatureSet

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/blocktree/go-owcdrivers/btcTransaction"
	"github.com/blocktree/go-owcrypt"
)

//signTxHash 签名交易单哈希
func SignTxHash(symbol string, msg []byte, privateKey []byte, eccType uint32) ([]byte, error) {
	var sig []byte
	if strings.EqualFold(symbol, "ETH") || strings.EqualFold(symbol, "TRUE") {
		sig, err := owcrypt.ETHsignature(privateKey, msg)
		if err != owcrypt.SUCCESS {
			return nil, fmt.Errorf("ETH sign hash failed")
		}
		return sig, nil
	}

	if strings.EqualFold(symbol, "NAS") {
		sig, err := owcrypt.NAS_signature(privateKey, msg)
		if err != owcrypt.SUCCESS {
			return nil, fmt.Errorf("NAS sign hash failed")
		}
		return sig, nil
	}

	if strings.EqualFold(symbol, "VSYS") {
		sig, err := VSYSSignature(privateKey, msg)
		if err != owcrypt.SUCCESS {
			return nil, fmt.Errorf("VSYS sign hash failed")
		}
		return sig, nil
	}

	if strings.EqualFold(symbol, "TRX") {
		sig, err := TronSignature(privateKey, msg)
		if err != owcrypt.SUCCESS {
			return nil, fmt.Errorf("TRX sign hash failed")
		}
		return sig, nil
	}

	sig, err := owcrypt.Signature(privateKey, nil, 0, msg, uint16(len(msg)), eccType)
	if err != owcrypt.SUCCESS {
		return nil, fmt.Errorf("ECC sign hash failed")
	}
	sig = serilizeS(sig)
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
