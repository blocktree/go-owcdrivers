package omniTransaction

import (
	"errors"
)

type Transaction struct {
	Version  []byte
	Vins     []TxIn
	Vouts    []TxOut
	LockTime []byte
	Witness  bool
}

func newEmptyTransaction(vins []Vin, vouts []Vout, omniDetail OmniStruct, lockTime uint32, replaceable bool, addressPrefix AddressPrefix) (*Transaction, error) {
	txIn, err := newTxInForEmptyTrans(vins)
	if err != nil {
		return nil, err
	}

	for i := 0; i < len(txIn); i++ {
		txIn[i].setSequence(lockTime, replaceable)
	}

	txOut, err := newTxOutForEmptyTrans(vouts, omniDetail, addressPrefix)
	if err != nil {
		return nil, err
	}

	version := uint32ToLittleEndianBytes(DefaultTxVersion)
	locktime := uint32ToLittleEndianBytes(lockTime)

	return &Transaction{version, txIn, txOut, locktime, false}, nil
}

func (t Transaction) encodeToBytes(SegwitON bool) ([]byte, error) {
	if t.Vins == nil || len(t.Vins) == 0 {
		return nil, errors.New("No input found in the transaction struct!")
	}

	if t.Vouts == nil || len(t.Vouts) == 0 {
		return nil, errors.New("No output found in the transaction struct!")
	}

	if t.Version == nil || len(t.Version) != 4 {
		return nil, errors.New("Invalid transaction version data!")
	}

	if t.LockTime == nil || len(t.LockTime) != 4 {
		return nil, errors.New("Invalid loack time data!")
	}

	ret := []byte{}
	ret = append(ret, t.Version...)

	if t.Witness {
		ret = append(ret, SegWitSymbol, SegWitVersion)
	}

	ret = append(ret, byte(len(t.Vins)))
	for _, in := range t.Vins {
		inBytes, err := in.toBytes(SegwitON)
		if err != nil {
			return nil, err
		}
		ret = append(ret, inBytes...)
	}

	ret = append(ret, byte(len(t.Vouts)))

	for _, out := range t.Vouts {
		outBytes, err := out.toBytes()
		if err != nil {
			return nil, err
		}
		ret = append(ret, outBytes...)
	}

	if t.Witness {
		for _, in := range t.Vins {
			swBytes, err := in.toSegwitBytes()
			if err != nil {
				return nil, err
			}
			ret = append(ret, swBytes...)
		}
	}
	ret = append(ret, t.LockTime...)
	return ret, nil
}

func DecodeRawTransaction(txBytes []byte, SegwitON bool) (*Transaction, error) {
	limit := len(txBytes)

	if limit == 0 {
		return nil, errors.New("Invalid transaction data!")
	}

	var rawTx Transaction

	index := 0

	if index+4 > limit {
		return nil, errors.New("Invalid transaction data length!")
	}

	rawTx.Version = txBytes[index : index+4]
	index += 4

	if littleEndianBytesToUint32(rawTx.Version) != DefaultTxVersion {
		return nil, errors.New("Only transaction version 2 is supported right now!")
	}

	if index+2 > limit {
		return nil, errors.New("Invalid transaction data length!")
	}
	if txBytes[index] == SegWitSymbol {
		if txBytes[index+1] != SegWitVersion {
			return nil, errors.New("Invalid witness symbol!")
		}
		rawTx.Witness = true
		index += 2
	}

	if index+1 > limit {
		return nil, errors.New("Invalid transaction data length!")
	}
	numOfVins := txBytes[index]
	index++
	if numOfVins == 0 {
		return nil, errors.New("Invalid transaction data!")
	}

	for i := byte(0); i < numOfVins; i++ {
		var tmpTxIn TxIn

		if index+32 > limit {
			return nil, errors.New("Invalid transaction data length!")
		}
		tmpTxIn.TxID = txBytes[index : index+32]
		index += 32

		if index+4 > limit {
			return nil, errors.New("Invalid transaction data length!")
		}
		tmpTxIn.Vout = txBytes[index : index+4]
		index += 4

		if index+1 > limit {
			return nil, errors.New("Invalid transaction data length!")
		}
		scriptLen := int(txBytes[index])
		index++

		if scriptLen == 0 {
			tmpTxIn.scriptPub = nil
			tmpTxIn.scriptSig = nil
			if rawTx.Witness {
				tmpTxIn.inType = TypeBech32
			} else {
				tmpTxIn.inType = TypeEmpty
			}
		} else if scriptLen == 0x17 {
			if !rawTx.Witness {
				return nil, errors.New("Invalid transaction data!")
			}
			tmpTxIn.inType = TypeP2WPKH
			if index+scriptLen > limit {
				return nil, errors.New("Invalid transaction data length!")
			}
			tmpTxIn.scriptPub = txBytes[index : index+scriptLen]
			index += int(scriptLen)
		} else if scriptLen == 0x23 {
			if !rawTx.Witness {
				return nil, errors.New("Invalid transaction data!")
			}
			tmpTxIn.inType = TypeMultiSig
			if index+scriptLen > limit {
				return nil, errors.New("Invalid transaction data length!")
			}
			tmpTxIn.scriptPub = append([]byte{0x23}, txBytes[index:index+scriptLen]...)
			index += int(scriptLen)
		} else if scriptLen <= 0x6C {
			tmpTxIn.inType = TypeP2PKH
			if index+scriptLen > limit {
				return nil, errors.New("Invalid transaction data length!")
			}
			tmpTxIn.scriptSig = txBytes[index : index+scriptLen]
			index += int(scriptLen)
		} else {
			if rawTx.Witness {
				return nil, errors.New("Invalid transaction data!")
			}
			tmpTxIn.inType = TypeMultiSig
			if scriptLen == 0xFD {
				if index+2 > limit {
					return nil, errors.New("Invalid transaction data length!")
				}
				scriptLen = int(littleEndianBytesToUint16(txBytes[index : index+2]))
				if index+scriptLen > limit {
					return nil, errors.New("Invalid transaction data length!")
				}
				tmpTxIn.scriptMulti = append([]byte{0xFD}, txBytes[index:index+scriptLen+2]...)
				index += scriptLen + 2
			} else if scriptLen > 0xFD {
				return nil, errors.New("Invalid transaction data!")
			} else {
				if index+scriptLen > limit {
					return nil, errors.New("Invalid transaction data length!")
				}
				tmpTxIn.scriptMulti = append(tmpTxIn.scriptMulti, txBytes[index:index+scriptLen]...)
				index += scriptLen
			}
		}

		tmpTxIn.sequence = txBytes[index : index+4]
		index += 4
		rawTx.Vins = append(rawTx.Vins, tmpTxIn)
	}

	if index+1 > limit {
		return nil, errors.New("Invalid transaction data length!")
	}

	numOfVouts := txBytes[index]
	index++
	if numOfVouts == 0 {
		return nil, errors.New("Invalid transaction data!")
	}

	for i := byte(0); i < numOfVouts; i++ {
		var tmpTxOut TxOut

		if index+8 > limit {
			return nil, errors.New("Invalid transaction data length!")
		}
		tmpTxOut.amount = txBytes[index : index+8]
		index += 8

		if index+1 > limit {
			return nil, errors.New("Invalid transaction data length!")
		}
		lockScriptLen := txBytes[index]
		index++

		if lockScriptLen == 0 {
			return nil, errors.New("Invalid transaction data!")
		}

		if index+int(lockScriptLen) > limit {
			return nil, errors.New("Invalid transaction data length!")
		}
		tmpTxOut.lockScript = txBytes[index : index+int(lockScriptLen)]
		index += int(lockScriptLen)

		rawTx.Vouts = append(rawTx.Vouts, tmpTxOut)
	}

	if rawTx.Witness {
		for i := byte(0); i < numOfVins; i++ {
			if index+1 > limit {
				return nil, errors.New("Invalid transaction data length!")
			}
			if rawTx.Vins[i].inType == TypeP2PKH {
				if txBytes[index] != 0x00 {
					return nil, errors.New("Invalid transaction data!")
				}
				index++
			} else if rawTx.Vins[i].inType == TypeP2WPKH || rawTx.Vins[i].inType == TypeBech32 {
				if txBytes[index] != 0x02 {
					return nil, errors.New("Invalid transaction data!")
				}
				index++
				if index+1 > limit {
					return nil, errors.New("Invalid transaction data length!")
				}
				sigLen := int(txBytes[index])
				if index+sigLen+35 > limit {
					return nil, errors.New("Invalid transaction data length!")
				}
				rawTx.Vins[i].scriptSig = txBytes[index : index+sigLen+35]

				index += sigLen + 35
			} else if rawTx.Vins[i].inType == TypeMultiSig {
				if !SegwitON {
					return nil, errors.New("Invalid transaction data!")
				}
				if txBytes[index] != 0x04 {
					return nil, errors.New("Invalid transaction data!")
				}
				index++
				if !SegwitON {
					scriptLen := int(txBytes[index])
					if scriptLen == 0xFD {
						if index+2 > limit {
							return nil, errors.New("Invalid transaction data!")
						}
						scriptLen = int(littleEndianBytesToUint16(txBytes[index+1 : index+3]))
						index += 3
					} else if scriptLen > 0xFD {
						return nil, errors.New("Invalid transaction data!")
					} else {
						index++
					}
				}

				if txBytes[index] != 0x00 {
					return nil, errors.New("Invalid transaction data!")
				}
				rawTx.Vins[i].scriptMulti = []byte{0x00}
				index++

				for {
					if index+2 > limit {
						return nil, errors.New("Invalid transaction data!")
					}
					if txBytes[index+1] != 0x30 {
						break
					}
					sigLen := txBytes[index]
					rawTx.Vins[i].scriptMulti = append(rawTx.Vins[i].scriptMulti, sigLen)
					index++
					if index+int(sigLen) > limit {
						return nil, errors.New("Invalid transaction data!")
					}
					rawTx.Vins[i].scriptMulti = append(rawTx.Vins[i].scriptMulti, txBytes[index:index+int(sigLen)]...)
					index += int(sigLen)
				}
				if index+1 > limit {
					return nil, errors.New("Invalid transaction data!")
				}
				redeemLen := 0
				if !SegwitON {
					if txBytes[index] == OpPushData1 {
						rawTx.Vins[i].scriptMulti = append(rawTx.Vins[i].scriptMulti, OpPushData1)
						index++
						if index+1 > limit {
							return nil, errors.New("Invalid transaction data!")
						}
						redeemLen = int(txBytes[index])
						rawTx.Vins[i].scriptMulti = append(rawTx.Vins[i].scriptMulti, txBytes[index])
						index++
					} else if txBytes[index] == OpPushData2 {
						rawTx.Vins[i].scriptMulti = append(rawTx.Vins[i].scriptMulti, OpPushData2)
						index++
						if index+2 > limit {
							return nil, errors.New("Invalid transaction data!")
						}
						redeemLen = int(littleEndianBytesToUint16(txBytes[index : index+2]))
						rawTx.Vins[i].scriptMulti = append(rawTx.Vins[i].scriptMulti, txBytes[index:index+2]...)
						index += 2
					} else {
						redeemLen = int(txBytes[index])
						rawTx.Vins[i].scriptMulti = append(rawTx.Vins[i].scriptMulti, txBytes[index])
						index++
					}
				} else {
					redeemLen = int(txBytes[index])
					rawTx.Vins[i].scriptMulti = append(rawTx.Vins[i].scriptMulti, txBytes[index])
					index++
				}

				if index+int(redeemLen) > limit {
					return nil, errors.New("Invalid transaction data!")
				}
				if txBytes[index+int(redeemLen)-1] != OpCheckMultiSig {
					return nil, errors.New("Invalid transaction data!")
				}
				rawTx.Vins[i].scriptMulti = append(rawTx.Vins[i].scriptMulti, txBytes[index:index+int(redeemLen)]...)
				index += redeemLen
			}
		}
	}

	if index+4 > limit {
		return nil, errors.New("Invalid transaction data length!")
	}
	rawTx.LockTime = txBytes[index : index+4]
	index += 4

	if index != limit {
		return nil, errors.New("Too much transaction data!")
	}
	return &rawTx, nil
}

func isSegwit(unlockData []TxUnlock, SegwitON bool) (bool, error) {
	if unlockData == nil || len(unlockData) == 0 {
		return false, errors.New("No lockscript or redeem script found!")
	}
	for _, u := range unlockData {
		_, _, inType, err := checkScriptType(u.LockScript, u.RedeemScript)
		if err != nil {
			return false, err
		}

		if inType == TypeP2WPKH || inType == TypeBech32 || (inType == TypeMultiSig && SegwitON) {
			return true, nil
		}
	}
	return false, nil
}

func (t Transaction) cloneEmpty() Transaction {
	var ret Transaction
	ret.Version = append(ret.Version, t.Version...)
	ret.Vins = append(ret.Vins, t.Vins...)
	ret.Vouts = append(ret.Vouts, t.Vouts...)
	ret.LockTime = append(ret.LockTime, t.LockTime...)
	ret.Witness = false
	for i := 0; i < len(ret.Vins); i++ {
		ret.Vins[i].setEmpty()
	}
	return ret
}
